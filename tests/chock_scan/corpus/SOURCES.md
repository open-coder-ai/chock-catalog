# yamlpath corpus

Real files the scanner must read exactly as PyYAML's event stream reads them
(`tests/chock_scan/test_yamlpath_corpus.py`). Each file under `vendor/` is the upstream
file byte for byte, fetched on 2026-10-02 from the default branch named below; the
licence each is used under is copied, unchanged, into `vendor/LICENSES/`. Nothing here
is executed: the files are test input only.

| file | upstream | licence |
|---|---|---|
| `github-actions/python-package.yml` | actions/starter-workflows `main:ci/python-package.yml` | MIT (`actions-starter-workflows-MIT.txt`) |
| `github-actions/docker-publish.yml` | actions/starter-workflows `main:ci/docker-publish.yml` | MIT |
| `github-actions/codeql.yml` | actions/starter-workflows `main:code-scanning/codeql.yml` | MIT |
| `github-actions/aws.yml` | actions/starter-workflows `main:deployments/aws.yml` | MIT |
| `docker-compose/nginx-flask-mysql.yaml` | docker/awesome-compose `master:nginx-flask-mysql/compose.yaml` | CC0-1.0 (`docker-awesome-compose-CC0-1.0.txt`) |
| `docker-compose/react-express-mongodb.yaml` | docker/awesome-compose `master:react-express-mongodb/compose.yaml` | CC0-1.0 |
| `kubernetes/nginx-app.yaml` | kubernetes/website `main:content/en/examples/application/nginx-app.yaml` | CC-BY-4.0 (`kubernetes-website-CC-BY-4.0.txt`), (c) The Kubernetes Authors |
| `kubernetes/security-context.yaml` | kubernetes/website `main:content/en/examples/pods/security/security-context.yaml` | CC-BY-4.0, (c) The Kubernetes Authors |
| `kubernetes/redis-leader-deployment.yaml` | kubernetes/website `main:content/en/examples/application/guestbook/redis-leader-deployment.yaml` | CC-BY-4.0, (c) The Kubernetes Authors |
| `kubernetes/ingress-nginx-deploy.yaml` | kubernetes/ingress-nginx `main:deploy/static/provider/cloud/deploy.yaml` | Apache-2.0 (`kubernetes-ingress-nginx-Apache-2.0.txt`) |
| `kubernetes/ingress-nginx-chart-values.yaml` | kubernetes/ingress-nginx `main:charts/ingress-nginx/values.yaml` | Apache-2.0 |
| `cloudformation/ec2-instance-with-security-group.yaml` | aws-cloudformation/aws-cloudformation-templates `main:EC2/EC2InstanceWithSecurityGroupSample.yaml` | Apache-2.0 (`aws-cloudformation-templates-Apache-2.0.txt`) |
| `cloudformation/vpc-with-managed-nat.yaml` | aws-cloudformation/aws-cloudformation-templates `main:VPC/VPC_With_Managed_NAT_And_Private_Subnet.yaml` | Apache-2.0 |
| `gitlab-ci/Python.gitlab-ci.yml` | gitlab-org/gitlab `master:lib/gitlab/ci/templates/Python.gitlab-ci.yml` | MIT (`gitlab-MIT.txt`) |
| `gitlab-ci/Docker.gitlab-ci.yml` | gitlab-org/gitlab `master:lib/gitlab/ci/templates/Docker.gitlab-ci.yml` | MIT |
| `gitlab-ci/SAST.gitlab-ci.yml` | gitlab-org/gitlab `master:lib/gitlab/ci/templates/Jobs/SAST.gitlab-ci.yml` | MIT |
| `dependabot/dependabot-core.yml` | dependabot/dependabot-core `main:.github/dependabot.yml` | MIT (`dependabot-core-MIT.txt`) |

Every `*.yml`/`*.yaml` file in this repository's tree (outside `.git` and tool caches) is
read the same way and must be readable, so the catalog's own workflows, dependabot config,
manifests and eval suites are corpus too.
