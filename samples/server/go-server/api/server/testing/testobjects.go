// Copyright 2017 The Grafeas Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package testutil

import (
	"fmt"

	pb "github.com/grafeas/grafeas/v1alpha1/proto"
	opspb "google.golang.org/genproto/googleapis/longrunning"
)

func Note(pID string) *pb.Note {
	return &pb.Note{
		Name:             fmt.Sprintf("projects/%s/notes/CVE-1999-0710", pID),
		ShortDescription: "CVE-2014-9911",
		LongDescription:  "NIST vectors: AV:N/AC:L/Au:N/C:P/I:P",
		Kind:             pb.Note_PACKAGE_VULNERABILITY,
		NoteType: &pb.Note_VulnerabilityType{
			&pb.VulnerabilityType{
				CvssScore: 7.5,
				Severity:  pb.VulnerabilityType_HIGH,
				Details: []*pb.VulnerabilityType_Detail{
					&pb.VulnerabilityType_Detail{
						CpeUri:  "cpe:/o:debian:debian_linux:7",
						Package: "icu",
						Description: "Stack-based buffer overflow in the ures_getByKeyWithFallback function in " +
							"common/uresbund.cpp in International Components for Unicode (ICU) before 54.1 for C/C++ allows " +
							"remote attackers to cause a denial of service or possibly have unspecified other impact via a crafted uloc_getDisplayName call.",
						MinAffectedVersion: &pb.VulnerabilityType_Version{
							Kind: pb.VulnerabilityType_Version_MINIMUM,
						},
						SeverityName: "HIGH",

						FixedLocation: &pb.VulnerabilityType_VulnerabilityLocation{
							CpeUri:  "cpe:/o:debian:debian_linux:7",
							Package: "icu",
							Version: &pb.VulnerabilityType_Version{
								Name:     "4.8.1.1",
								Revision: "12+deb7u6",
							},
						},
					},
					&pb.VulnerabilityType_Detail{
						CpeUri:  "cpe:/o:debian:debian_linux:8",
						Package: "icu",
						Description: "Stack-based buffer overflow in the ures_getByKeyWithFallback function in " +
							"common/uresbund.cpp in International Components for Unicode (ICU) before 54.1 for C/C++ allows " +
							"remote attackers to cause a denial of service or possibly have unspecified other impact via a crafted uloc_getDisplayName call.",
						MinAffectedVersion: &pb.VulnerabilityType_Version{
							Kind: pb.VulnerabilityType_Version_MINIMUM,
						},
						SeverityName: "HIGH",

						FixedLocation: &pb.VulnerabilityType_VulnerabilityLocation{
							CpeUri:  "cpe:/o:debian:debian_linux:8",
							Package: "icu",
							Version: &pb.VulnerabilityType_Version{
								Name:     "52.1",
								Revision: "8+deb8u4",
							},
						},
					},
					&pb.VulnerabilityType_Detail{
						CpeUri:  "cpe:/o:debian:debian_linux:9",
						Package: "icu",
						Description: "Stack-based buffer overflow in the ures_getByKeyWithFallback function in " +
							"common/uresbund.cpp in International Components for Unicode (ICU) before 54.1 for C/C++ allows " +
							"remote attackers to cause a denial of service or possibly have unspecified other impact via a crafted uloc_getDisplayName call.",
						MinAffectedVersion: &pb.VulnerabilityType_Version{
							Kind: pb.VulnerabilityType_Version_MINIMUM,
						},
						SeverityName: "HIGH",

						FixedLocation: &pb.VulnerabilityType_VulnerabilityLocation{
							CpeUri:  "cpe:/o:debian:debian_linux:9",
							Package: "icu",
							Version: &pb.VulnerabilityType_Version{
								Name:     "55.1",
								Revision: "3",
							},
						},
					},
					&pb.VulnerabilityType_Detail{
						CpeUri:  "cpe:/o:canonical:ubuntu_linux:14.04",
						Package: "andriod",
						Description: "Stack-based buffer overflow in the ures_getByKeyWithFallback function in " +
							"common/uresbund.cpp in International Components for Unicode (ICU) before 54.1 for C/C++ allows " +
							"remote attackers to cause a denial of service or possibly have unspecified other impact via a crafted uloc_getDisplayName call.",
						MinAffectedVersion: &pb.VulnerabilityType_Version{
							Kind: pb.VulnerabilityType_Version_MINIMUM,
						},
						SeverityName: "MEDIUM",

						FixedLocation: &pb.VulnerabilityType_VulnerabilityLocation{
							CpeUri:  "cpe:/o:canonical:ubuntu_linux:14.04",
							Package: "andriod",
							Version: &pb.VulnerabilityType_Version{
								Kind: pb.VulnerabilityType_Version_MAXIMUM,
							},
						},
					},
				},
			},
		},
		RelatedUrl: []*pb.Note_RelatedUrl{
			&pb.Note_RelatedUrl{
				Url:   "https://security-tracker.debian.org/tracker/CVE-2014-9911",
				Label: "More Info",
			},
			&pb.Note_RelatedUrl{
				Url:   "http://people.ubuntu.com/~ubuntu-security/cve/CVE-2014-9911",
				Label: "More Info",
			},
		},
	}
}

func Occurrence(pID, noteName string) *pb.Occurrence {
	return &pb.Occurrence{
		Name:        fmt.Sprintf("projects/%s/occurrences/134", pID),
		ResourceUrl: "gcr.io/foo/bar",
		NoteName:    noteName,
		Kind:        pb.Note_PACKAGE_VULNERABILITY,
		Details: &pb.Occurrence_VulnerabilityDetails{
			VulnerabilityDetails: &pb.VulnerabilityType_VulnerabilityDetails{
				Severity:  pb.VulnerabilityType_HIGH,
				CvssScore: 7.5,
				PackageIssue: []*pb.VulnerabilityType_PackageIssue{
					&pb.VulnerabilityType_PackageIssue{
						SeverityName: "HIGH",
						AffectedLocation: &pb.VulnerabilityType_VulnerabilityLocation{
							CpeUri:  "cpe:/o:debian:debian_linux:8",
							Package: "icu",
							Version: &pb.VulnerabilityType_Version{
								Name:     "52.1",
								Revision: "8+deb8u3",
							},
						},
						FixedLocation: &pb.VulnerabilityType_VulnerabilityLocation{
							CpeUri:  "cpe:/o:debian:debian_linux:8",
							Package: "icu",
							Version: &pb.VulnerabilityType_Version{
								Name:     "52.1",
								Revision: "8+deb8u4",
							},
						},
					},
				},
			},
		},
	}
}

func Build_Note(pID string) *pb.Note {
	return &pb.Note{
		Name:             fmt.Sprintf("projects/%s/notes/it-devops-node-ts-mocha-example", pID),
		ShortDescription: "it-devops-node-ts-mocha-example",
		LongDescription:  "build: it-devops-node-ts-mocha-example",
		Kind:             pb.Note_BUILD_DETAILS,
		NoteType: &pb.Note_BuildType{
			&pb.BuildType{
				BuilderVersion: "drone",
				Signature: &pb.BuildSignature{ // Signature of the build in Occurrences pointing to the Note containing this `BuilderDetails`.
					// PublicKey: <>
					// Signature: <>
					KeyId: "key9784659746513",
					// KeyType: pb.BuildSignature_PKIX_PEM, // Can be unspecified
				},
			},
		},
	}
}

func Build_Occurrence(pID, noteName string) *pb.Occurrence {
	return &pb.Occurrence{
		Name:        fmt.Sprintf("projects/%s/occurrences/devops-node-ts-mocha-example-build-216", pID),
		ResourceUrl: "https://drone/it/devops-node-ts-mocha-example/216",
		NoteName:    noteName, //projects/drone/notes/it-devops-node-ts-mocha-example
		Kind:        pb.Note_BUILD_DETAILS,
		Details: &pb.Occurrence_BuildDetails{
			BuildDetails: &pb.BuildDetails{
				Provenance: &pb.BuildProvenance{
					Id:        "devops-node-ts-mocha-example-build-216",
					ProjectId: pID,
					BuiltArtifacts: []*pb.Artifact{
						&pb.Artifact{
							Name:     "devops-node-mocha-example-0.1.0.tgz",
							Checksum: "7622d020e4e43d8c322ef55c12f20e1c",
							Id:       "artifacts.com/someimage@sha256:7622d020e4e43d8c322ef55c12f20e1c",
						},
					},
					// CreateTime: "ss",
					// StartTime:  "ss",
					// FinishTime: "ss",
					Creator: "name.surname@example.com",
					// LogsBucket: "",
					// SourceProvenance: "",
					// TriggerId: "",
					// BuildOptions: "",
					// BuilderVersion: "",
				},
				ProvenanceBytes: "{\"id\":\"devops-node-ts-mocha-example-build-216\",\"project_id\":\"drone :: it :: devops-node-ts-mocha-example\",\"built_artifacts\":[{\"name\":\"devops-node-mocha-example-0.1.0.tgz\",\"checksum\":\"7622d020e4e43d8c322ef55c12f20e1c\"}],\"creator\":\"lukas.supienis@adform.com\",\"source_provenance\":{\"Source\":null,\"context\":{\"Context\":{\"Git\":{\"url\":\"https://gitz.adform.com/it/devops-node-ts-mocha-example/commit/131170b9bf5f507838d76a3da08d6a305d036ed9\",\"revision_id\":\"refs/heads/test/grafeas\"}}}},\"builder_version\":\"drone\"}",
			},
		},
	}
}

func Deployment_Note(pID string) *pb.Note {
	return &pb.Note{
		Name:             fmt.Sprintf("projects/%s/notes/it-devops-node-ts-mocha-example-deployment", pID),
		ShortDescription: "it-devops-node-ts-mocha-example",
		LongDescription:  "it-devops-node-ts-mocha-example deployment",
		Kind:             pb.Note_DEPLOYABLE,
		NoteType: &pb.Note_Deployable{
			&pb.Deployable{
				ResourceUri: []string{
					"artifacts.com/someimage@sha256:7622d020e4e43d8c322ef55c12f20e1c",
					"artifacts.com/someimage@sha256:7622d020e4e43d8c322ef55c12f20e1d",
				},
			},
		},
	}
}

func Deployment_Occurrence(pID, noteName string) *pb.Occurrence {
	return &pb.Occurrence{
		Name:        fmt.Sprintf("projects/%s/occurrences/devops-node-ts-mocha-example-deployment-216", pID),
		ResourceUrl: "artifacts.com/someimage@sha256:7622d020e4e43d8c322ef55c12f20e1c",
		NoteName:    noteName, //projects/drone/notes/it-devops-node-ts-mocha-example
		Kind:        pb.Note_DEPLOYABLE,
		Details: &pb.Occurrence_DeploymentDetails{
			DeploymentDetails: &pb.Deployable_DeploymentDetails{
				UserEmail: "name.surname@example.com",
				// DeployTime:   "",
				// UndeployTime: "",
				Config:   "config string",
				Address:  "Address of the runtime element hosting this deployment.",
				Platform: pb.Deployable_DeploymentDetails_CUSTOM,
			},
		},
	}
}

func Operation(pID string) *opspb.Operation {
	// md := &pb.OperationMetadata{CreateTime: ptypes.TimestampNow()}
	// bytes, err := proto.Marshal(md)
	// if err != nil {
	// 	log.Printf("Error parsing bytes: %v", err)
	// 	return nil
	// }
	return &opspb.Operation{
		Name: fmt.Sprintf("projects/%s/operations/foo", pID),
		// Metadata: &any.Any{Value: bytes},
		Done: false,
	}
}
