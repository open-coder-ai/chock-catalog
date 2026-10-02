# HCL scanner corpus: sources and licences

Real Terraform, OpenTofu and Packer files, copied byte for byte (renamed only: a path's `/` became
`-`) so `tests/chock_scan/test_hcl_corpus.py` can show `chock_scan.hcl` and `chock_scan.hcl_json`
read them. They are test data: never executed, never shipped (`tests/` is not published).

`valid/` and the module folders must parse; `invalid/` holds files with a syntax error, each of which
must raise `HclError`.

| folder | source (commit) | licence |
|---|---|---|
| `terraform-aws-security-group/` | github.com/terraform-aws-modules/terraform-aws-security-group (`b3c1b2e8beff9671960f874f5569d77c803b0127`) | Apache-2.0 |
| `terraform-aws-s3-bucket/` | github.com/terraform-aws-modules/terraform-aws-s3-bucket (`5dc2f1f89743ab935114b0b039bc88044a672ca2`) | Apache-2.0 |
| `terraform-aws-iam/` | github.com/terraform-aws-modules/terraform-aws-iam (`55514b7873c411040395e024a422684998da77c2`) | Apache-2.0 |
| `terraform-aws-vpc/` | github.com/terraform-aws-modules/terraform-aws-vpc (`b3abd6df2ecf052451a361ed55b8f06f8742a795`) | Apache-2.0 |
| `packer-plugin-amazon/` | github.com/hashicorp/packer-plugin-amazon (`62c6d423e4127f2f8bb83cb2dfc1501eca2efdf7`) | MPL-2.0 |
| `opentofu/` | github.com/opentofu/opentofu, `internal/configs/testdata/` (`9ffbb1c211bfb36775c5923809a18289396ee0c1`) | MPL-2.0 |
| `hcl-specsuite/` | github.com/hashicorp/hcl, `specsuite/tests/` (`4c317722d9827407a50f3aec3bb40f43de59e87c`) | MPL-2.0 |

Apache-2.0: https://www.apache.org/licenses/LICENSE-2.0. MPL-2.0: https://mozilla.org/MPL/2.0/ --
the MPL-2.0 files are unmodified and their source is the repository named above. Copyright stays
with the respective authors.
