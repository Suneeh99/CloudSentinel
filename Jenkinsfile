pipeline {
  agent { label 'docker' }
  options {
    skipDefaultCheckout(true)
    disableConcurrentBuilds()
    timestamps()
    timeout(time: 45, unit: 'MINUTES')
  }
  parameters {
    booleanParam(name: 'PUBLISH_TO_ECR', defaultValue: false, description: 'Publish the tested image to an existing ECR repository')
    booleanParam(name: 'DEPLOY_TO_EKS', defaultValue: false, description: 'After approval, update an existing staging EKS deployment')
    string(name: 'AWS_ACCOUNT_ID', defaultValue: '', description: '12-digit AWS account ID')
    string(name: 'AWS_REGION', defaultValue: 'us-east-1', description: 'AWS region')
    string(name: 'ECR_REPOSITORY', defaultValue: 'cloudsentinel', description: 'Existing ECR repository')
    string(name: 'EKS_CLUSTER', defaultValue: '', description: 'Existing staging EKS cluster')
  }
  stages {
    stage('Checkout') {
      steps {
        checkout scm
        script {
          env.REVISION = sh(script: 'git rev-parse HEAD', returnStdout: true).trim()
          env.LOCAL_IMAGE = "cloudsentinel:${env.REVISION}"
        }
      }
    }
    stage('Quality gates') {
      steps { sh 'TEST_IMAGE="cloudsentinel:test-$BUILD_NUMBER" bash scripts/ci-container.sh' }
    }
    stage('Build runtime image') {
      steps { sh 'docker build --target runtime --label "org.opencontainers.image.revision=$REVISION" -t "$LOCAL_IMAGE" .' }
    }
    stage('Container integration checks') {
      steps { sh 'CLOUDSENTINEL_IMAGE="$LOCAL_IMAGE" bash scripts/container-smoke.sh' }
    }
    stage('Publish to ECR') {
      when { expression { params.PUBLISH_TO_ECR } }
      steps {
        script {
          if (!(params.AWS_ACCOUNT_ID ==~ /[0-9]{12}/) || !(params.AWS_REGION ==~ /[a-z]{2}-[a-z]+-[0-9]+/) || !(params.ECR_REPOSITORY ==~ /[a-z0-9][a-z0-9._\/-]*/)) {
            error('Invalid AWS account, region or ECR repository')
          }
          if (env.BRANCH_NAME != 'main') { error('Image publication requires the trusted main branch of a Multibranch Pipeline') }
          env.REGISTRY = "${params.AWS_ACCOUNT_ID}.dkr.ecr.${params.AWS_REGION}.amazonaws.com"
          env.REMOTE_IMAGE = "${env.REGISTRY}/${params.ECR_REPOSITORY}:${env.REVISION}"
        }
        sh '''
          set -eu
          export DOCKER_CONFIG="$(mktemp -d)"
          trap 'rm -rf "$DOCKER_CONFIG"' EXIT
          aws ecr get-login-password --region "$AWS_REGION" | docker login --username AWS --password-stdin "$REGISTRY"
          docker tag "$LOCAL_IMAGE" "$REMOTE_IMAGE"
          docker push "$REMOTE_IMAGE"
          aws ecr describe-images --region "$AWS_REGION" --repository-name "$ECR_REPOSITORY" --image-ids "imageTag=$REVISION" --query 'imageDetails[0].imageDigest' --output text > image-digest.txt
        '''
        archiveArtifacts artifacts: 'image-digest.txt', fingerprint: true
      }
    }
    stage('Deploy to existing staging EKS') {
      when { expression { params.DEPLOY_TO_EKS } }
      steps {
        script {
          if (!params.PUBLISH_TO_ECR) { error('Deployment requires publication of the tested image') }
          if (!(params.EKS_CLUSTER ==~ /[A-Za-z0-9][A-Za-z0-9_-]*/)) { error('Set a valid staging EKS cluster') }
          timeout(time: 10, unit: 'MINUTES') {
            input message: "Deploy ${env.REVISION} to staging cluster ${params.EKS_CLUSTER}?", ok: 'Deploy to staging'
          }
        }
        sh '''
          set -eu
          export KUBECONFIG="$(mktemp)"
          trap 'rm -f "$KUBECONFIG"' EXIT
          aws eks update-kubeconfig --name "$EKS_CLUSTER" --region "$AWS_REGION" --kubeconfig "$KUBECONFIG"
          digest="$(cat image-digest.txt)"
          printf '%s' "$digest" | grep -Eq '^sha256:[a-f0-9]{64}$'
          kubectl -n cloudsentinel set image deployment/cloudsentinel "app=$REGISTRY/$ECR_REPOSITORY@$digest"
          kubectl -n cloudsentinel rollout status deployment/cloudsentinel --timeout=180s
        '''
      }
    }
  }
  post {
    cleanup {
      sh 'docker image rm "cloudsentinel:test-$BUILD_NUMBER" >/dev/null 2>&1 || true'
    }
  }
}
