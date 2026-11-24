pipeline {
  agent any
  environment {
    IMAGE = 'lab-web:latest'
    NET   = 'lab-net'
  }
  stages {

    stage('Build') {
      steps {
        sh 'docker build -t $IMAGE .'
      }
    }

    stage('Static Analysis & Dependencies') {
      steps {
        sh '''
          mkdir -p reports
          # SAST con Bandit (revision de codigo)
          docker run --rm -v "$(pwd)":/src -w /src python:3.11-slim sh -c \
            "pip install -q bandit && bandit -r app.py init_db.py -f txt -o reports/bandit-report.txt || true"
          # Auditoria de dependencias con pip-audit
          docker run --rm -v "$(pwd)":/src -w /src python:3.11-slim sh -c \
            "pip install -q pip-audit && pip-audit -r requirements.txt > reports/pip-audit-report.txt 2>&1 || true"
        '''
        archiveArtifacts artifacts: 'reports/*.txt', allowEmptyArchive: true
      }
    }

    stage('Test - OWASP ZAP') {
      steps {
        sh '''
          docker network create $NET || true
          docker rm -f app-test || true
          docker run -d --name app-test --network $NET $IMAGE
          sleep 5
          mkdir -p zap-reports && chmod 777 zap-reports
          docker run --rm --network $NET -v "$(pwd)/zap-reports":/zap/wrk:rw \
            ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
            -t http://app-test:5000/login -r zap-report.html -I
        '''
      }
      post {
        always {
          sh 'docker rm -f app-test || true'
          publishHTML(target: [
            reportDir: 'zap-reports',
            reportFiles: 'zap-report.html',
            reportName: 'ZAP Report',
            keepAll: true,
            allowMissing: true,
            alwaysLinkToLastBuild: true
          ])
        }
      }
    }

    stage('Deploy') {
      steps {
        sh '''
          docker rm -f lab-web-prod || true
          docker network create $NET || true
          docker run -d --name lab-web-prod --network $NET -p 5000:5000 --restart unless-stopped $IMAGE
        '''
      }
    }
  }
}
