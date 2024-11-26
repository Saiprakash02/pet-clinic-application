pipeline {
    agent any
    tools {
        maven 'maven3'
        jdk 'jdk17'
        nodejs 'node16'
    }

    parameters {
        choice(name: 'OWASP_ZAP_SCAN_TYPE', choices: ['BASELINE', 'API', 'FULL'], 
               description: 'Select the OWASP ZAP scan type')

        string(name: 'ZAP_TARGET_URL', defaultValue: 'https://www.example.com', description: 'Enter the URL of the application to scan')
    }
    
    environment {
        SCANNER_HOME = tool 'sonarqube-scanner'
        NAME = 'saiprakash02/petclinicapp'
        BUILD_NUMBER = "${env.BUILD_NUMBER}"
        DEPENDENCY_CHECK_API_KEY = credentials('DP-key')
        def commitId = sh(script: 'git rev-parse --short HEAD', returnStdout: true).trim()
        def imageTag = "${commitId}-${BUILD_NUMBER}"
        IMAGE_NAME = "${NAME}:${imageTag}"
    }
    
    stages {
        stage('Maven Unit Test') {
            steps {
                sh "mvn clean test"
            }
        }

        stage('Maven Install') {
            steps {
                sh "mvn clean install"
            }
        }

        stage("Sonarqube Analysis") {
            steps {
                withSonarQubeEnv('sonar-server') {
                    sh '''
                        $SCANNER_HOME/bin/sonar-scanner \
                        -Dsonar.projectName=Petclinic-App \
                        -Dsonar.java.binaries=. \
                        -Dsonar.projectKey=Petclinic 
                    '''
                }
            }
        }

        stage("Quality Gate") {
            steps {
                script {
                    timeout(time: 10, unit: 'MINUTES') {
                        def qg = waitForQualityGate()
                        if (qg.status != 'OK') {
                            error "Pipeline aborted due to quality gate failure: ${qg.status}"
                        }
                    }
                }
            }
        }

        stage('OWASP Dependency Check') { 
            steps { 
                script { 
                    timeout(time: 60, unit: 'MINUTES') { 
                        dependencyCheck additionalArguments: '--scan ./ --nvdApiKey $DEPENDENCY_CHECK_API_KEY', odcInstallation: 'DP' 
                        dependencyCheckPublisher failedTotalCritical: 0, 
                                                failedTotalHigh: 0, 
                                                pattern: 'dependency-check-report.xml', 
                                                stopBuild: true, 
                                                unstableTotalCritical: 0, 
                                                unstableTotalHigh: 0 
                    } 
                } 
            } 
        }

        stage('Build Test') {
            steps {
                script {
                    sh 'mvn clean package'
                }
            }
        }

        stage('Creating Docker File') {
            steps {
                script {
                    writeFile file: 'Dockerfile', text: '''
FROM tomcat:9.0-jdk17
RUN groupadd -r appgroup && useradd -r -g appgroup -m -d /app appuser
RUN chown -R appuser:appgroup /usr/local/tomcat
WORKDIR /app
COPY .mvn/ .mvn
COPY mvnw pom.xml ./
RUN chmod +x mvnw
USER appuser
COPY src ./src
EXPOSE 8080
CMD ["./mvnw", "jetty:run-war"]
                    '''
                    sh 'cat Dockerfile'
                }
            }
        }

        stage('Hadolint Intilize') {
            steps {
                script {
                    sh 'docker run --rm -i hadolint/hadolint < Dockerfile > dockerfile_report.txt'
                    def reportFile = 'dockerfile_report.txt'
                    def reportContent = readFile(reportFile).trim()
                    if (reportContent.isEmpty()) {
                        sh 'echo "No issues found in Dockerfile." > dockerfile_report.txt'
                    }
                }
            }
        }

        stage('Archive Lint Results') {
            steps {
                script {
                    archiveArtifacts artifacts: 'dockerfile_report.txt', allowEmptyArchive: false
                }
            }
        }

        stage('Building Docker Image') {
            steps {
                script {
                    sh "docker build -t ${IMAGE_NAME} ."
                }
            }
        }

        stage('Scan Docker Image with Trivy') {
            steps {
                script {
                    sh "docker pull aquasec/trivy:0.56.2"
                    retry(10) {
                        try {
                            sh "docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -i aquasec/trivy:0.56.2 image ${IMAGE_NAME} > trivy_report.json"
                        } catch (Exception e) {
                            echo "Trivy scan failed: ${e.message}"
                            sleep 5
                            throw e
                        }
                    }
                }
            }
        }

        stage('Archive Trivy Scan Report') {
            steps {
                archiveArtifacts artifacts: 'trivy_report.json', allowEmptyArchive: false
            }
        }

        // stage('Check Vulnerabilities') {
        //     steps {
        //         script {
        //             def results = sh(script: "jq '[.[] | select(.vulnerabilities != null) | .vulnerabilities[] | select(.severity == \"HIGH\" or .severity == \"CRITICAL\")] | length' trivy_report.json", returnStdout: true)
        //             def highAndCriticalCount = results.trim()
        //             echo "High and Critical Vulnerabilities Count: ${highAndCriticalCount}"
        //             if (highAndCriticalCount.toInteger() > 0) {
        //                 error("High or Critical vulnerabilities detected. Failing the build.")
        //             } else {
        //                 echo "No High or Critical vulnerabilities detected."
        //             }
        //         }
        //     }
        // }
        stage('OWASP ZAP Scan') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    script {
                        echo "The OWASP ZAP Scan Type is ${params.OWASP_ZAP_SCAN_TYPE}"
                        def zapScanScript = ''
                        def zapTargetUrl = params.ZAP_TARGET_URL
                        if (params.OWASP_ZAP_SCAN_TYPE == 'BASELINE') {
                            zapScanScript = 'zap-baseline.py'
                        } else if (params.OWASP_ZAP_SCAN_TYPE == 'API') {
                            zapScanScript = 'zap-api-scan.py'
                        } else if (params.OWASP_ZAP_SCAN_TYPE == 'FULL') {
                            zapScanScript = 'zap-full-scan.py'
                        }

                        def status = sh(script: """#!/bin/bash
                        docker run -t ghcr.io/zaproxy/zaproxy:stable ${zapScanScript} \
                        -t ${zapTargetUrl} > ${OWASP_ZAP_SCAN_TYPE}_Owasp_Zap_report.html
                        """, returnStatus: true)

                        if (status == 0) {
                            echo "ZAP scan completed successfully."
                        } else {
                            error "ZAP scan failed with status code: ${status}"
                        }
                    }
                }
            }
        }
        stage('Archive Owasp Zap Report') {
            steps {
                archiveArtifacts artifacts: "${params.OWASP_ZAP_SCAN_TYPE}_Owasp_Zap_report.html", allowEmptyArchive: false
            }
        }
    }
}
