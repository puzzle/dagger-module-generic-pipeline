// PITCFlow - Pipeline Integrity, Trust & Compliance
//
// Secure and compliant software delivery with trust and integrity. 🚀
//
// This module contains ready to use pipelines.
// They build and deliver your software / project with security and compliance out of the box.

package main

import (
	"context"
	"dagger/pitc-flow/internal/dagger"
	"fmt"
	"sync"
)

type PitcFlow struct{}

// Returns a file containing the results of the lint command
func (m *PitcFlow) Lint(
	// Container to run the lint command
	container *dagger.Container,
	// Path to file containing lint results
	results string,
) *dagger.File {
	return container.File(results)
}

// Returns a directory containing the results of the test command
func (m *PitcFlow) Test(
	// Container to run the test command
	container *dagger.Container,
	// Path to directory containing test results
	results string,
) *dagger.Directory {
	return container.Directory(results)
}

// Returns a file containing the results of the security scan
func (m *PitcFlow) Sast(
	// Container to run the security scan
	container *dagger.Container,
	// Path to file containing the results of the security scan
	results string,
) *dagger.File {
	return container.File(results)
}

// Returns a Container built from the Dockerfile in the provided Directory
func (m *PitcFlow) Build(_ context.Context, dir *dagger.Directory) *dagger.Container {
	return dag.Container().
		WithDirectory("/src", dir).
		WithWorkdir("/src").
		Directory("/src").
		DockerBuild()
}

// Builds the container and creates a SBOM for it
func (m *PitcFlow) SbomBuild(ctx context.Context, dir *dagger.Directory) *dagger.File {
	container := m.Build(ctx, dir)
	return m.Sbom(container)
}

// Creates a SBOM for the container
func (m *PitcFlow) Sbom(container *dagger.Container) *dagger.File {
	trivy_container := dag.Container().
		From("aquasec/trivy").
		WithEnvVariable("TRIVY_JAVA_DB_REPOSITORY", "public.ecr.aws/aquasecurity/trivy-java-db")

	trivy := dag.Trivy(dagger.TrivyOpts{
		Container:          trivy_container,
		DatabaseRepository: "public.ecr.aws/aquasecurity/trivy-db",
	})

	return trivy.Container(container).
		Report("cyclonedx").
		WithName("cyclonedx.json")
}

// Scans the SBOM for vulnerabilities
func (m *PitcFlow) Vulnscan(sbom *dagger.File) *dagger.File {
	trivy_container := dag.Container().
		From("aquasec/trivy").
		WithEnvVariable("TRIVY_JAVA_DB_REPOSITORY", "public.ecr.aws/aquasecurity/trivy-java-db")

	trivy := dag.Trivy(dagger.TrivyOpts{
		Container:          trivy_container,
		DatabaseRepository: "public.ecr.aws/aquasecurity/trivy-db",
	})

	return trivy.Sbom(sbom).Report("json")
}

// Publish cyclonedx SBOM to Deptrack
func (m *PitcFlow) PublishToDeptrack(
	ctx context.Context,
	// SBOM file
	sbom *dagger.File,
	// deptrack address for publishing the SBOM https://deptrack.example.com/api/v1/bom
	address string,
	// deptrack API key
	apiKey *dagger.Secret,
	// deptrack project UUID
	projectUUID string,
) (string, error) {
	return dag.Container().
		From("curlimages/curl").
		WithFile("sbom.json", sbom).
		WithExec([]string{"curl", "-X", "POST", "-H", "'Content-Type: multipart/form-data'", "-H", fmt.Sprintf("'X-API-Key: %s'", apiKey), "-F", fmt.Sprintf("'project=%s'", projectUUID), "-F", "bom=@sbom.json", address}).
		Stdout(ctx)
}

// Publish the provided Container to the provided registry
func (m *PitcFlow) Publish(
	ctx context.Context,
	// Container to publish
	container *dagger.Container,
	// Registry address to publish to - formatted as [host]/[user]/[repo]:[tag]
	registryAddress string,
	// Username of the registry's account
	// +optional
	// +default=""
	registryUsername string,
	// API key, password or token to authenticate to the registry
	// +optional
	registryPassword *dagger.Secret,
) (string, error) {
	if registryUsername != "" && registryPassword != nil {
		container = container.WithRegistryAuth(registryAddress, registryUsername, registryPassword)
	}
	return container.Publish(ctx, registryAddress)
}

// Sign the published image using cosign (keyless)
func (m *PitcFlow) Sign(
	ctx context.Context,
	// Username of the registry's account
	registryUsername string,
	// API key, password or token to authenticate to the registry
	registryPassword *dagger.Secret,
	// Container image digest to sign
	digest string,
) (string, error) {
	return dag.Cosign().SignKeyless(ctx, digest, dagger.CosignSignKeylessOpts{RegistryUsername: registryUsername, RegistryPassword: registryPassword})
}

// Attests the SBOM using cosign (keyless)
func (m *PitcFlow) Attest(
	ctx context.Context,
	// Username of the registry's account
	registryUsername string,
	// API key, password or token to authenticate to the registry
	registryPassword *dagger.Secret,
	// Container image digest to attest
	digest string,
	// SBOM file
	predicate *dagger.File,
	// SBOM type
	sbomType string,
) (string, error) {
	return dag.Cosign().AttestKeyless(ctx, digest, predicate, dagger.CosignAttestKeylessOpts{RegistryUsername: registryUsername, RegistryPassword: registryPassword, SbomType: sbomType})
}

// Executes all the steps and returns a directory with the results
func (m *PitcFlow) Run(
	ctx context.Context,
	// source directory
	dir *dagger.Directory,
	// lint container
	lintContainer *dagger.Container,
	// lint report file name e.g. "lint.json"
	lintReport string,
	// sast container
	sastContainer *dagger.Container,
	// security scan report file name e.g. "/app/brakeman-output.tabs"
	sastReport string,
	// test container
	testContainer *dagger.Container,
	// test report folder name e.g. "/mnt/test/reports"
	testReportDir string,
	// registry username for publishing the container image
	registryUsername string,
	// registry password for publishing the container image
	registryPassword *dagger.Secret,
	// registry address registry/repository/image:tag
	registryAddress string,
	// deptrack address for publishing the SBOM https://deptrack.example.com/api/v1/bom
	dtAddress string,
	// deptrack project UUID
	dtProjectUUID string,
	// deptrack API key
	dtApiKey *dagger.Secret,
	// ignore linter failures
	// +optional
	// +default=false
	pass bool,
) (*dagger.Directory, error) {
	var wg sync.WaitGroup
	wg.Add(5)

	var lintOutput = func() *dagger.File {
		defer wg.Done()
		return m.Lint(lintContainer, lintReport)
	}()

	var securityScan = func() *dagger.File {
		defer wg.Done()
		return m.Sast(sastContainer, sastReport)
	}()

	var vulnerabilityScan = func() *dagger.File {
		defer wg.Done()
		return m.Vulnscan(m.SbomBuild(ctx, dir))
	}()

	var image = func() *dagger.Container {
		defer wg.Done()
		return m.Build(ctx, dir)
	}()

	var testReports = func() *dagger.Directory {
		defer wg.Done()
		return m.Test(testContainer, testReportDir)
	}()

	// This Blocks the execution until its counter become 0
	wg.Wait()

	// Get the names of the files to fail on errors of the functions
	lintOutputName, err := lintOutput.Name(ctx)
	if err != nil {
		return nil, err
	}
	securityScanName, err := securityScan.Name(ctx)
	if err != nil {
		return nil, err
	}
	vulnerabilityScanName, err := vulnerabilityScan.Name(ctx)
	if err != nil {
		return nil, err
	}

	// After linting, scanning and testing is done, we can create the sbom and publish the image
	wg.Add(2)

	var sbom = func() *dagger.File {
		defer wg.Done()
		return m.Sbom(image)
	}()

	digest, err := func() (string, error) {
		defer wg.Done()
		return m.Publish(ctx, image, registryAddress, registryUsername, registryPassword)
	}()

	// This Blocks the execution until its counter become 0
	wg.Wait()

	if err == nil {
		// After publishing the image, we can sign and attest
		wg.Add(3)

		_, dtErr := func() (string, error) {
			defer wg.Done()
			return m.PublishToDeptrack(ctx, sbom, dtAddress, dtApiKey, dtProjectUUID)
		}()

		_, signErr := func() (string, error) {
			defer wg.Done()
			return m.Sign(ctx, registryUsername, registryPassword, digest)
		}()

		_, attErr := func() (string, error) {
			defer wg.Done()
			return m.Attest(ctx, registryUsername, registryPassword, digest, sbom, "cyclonedx")
		}()

		// This Blocks the execution until its counter become 0
		wg.Wait()

		if dtErr != nil || signErr != nil || attErr != nil {
			err = fmt.Errorf("one or more errors occurred: dtErr=%w, signErr=%w, attErr=%w", dtErr, signErr, attErr)
		}
	}

	errorString := ""
	if err != nil {
		errorString = err.Error()
	}

	sbomName, _ := sbom.Name(ctx)
	result_container := dag.Container().
		WithWorkdir("/tmp/out").
		WithFile(fmt.Sprintf("/tmp/out/lint/%s", lintOutputName), lintOutput).
		WithFile(fmt.Sprintf("/tmp/out/scan/%s", securityScanName), securityScan).
		WithDirectory("/tmp/out/unit-tests/", testReports).
		WithFile(fmt.Sprintf("/tmp/out/vuln/%s", vulnerabilityScanName), vulnerabilityScan).
		WithFile(fmt.Sprintf("/tmp/out/sbom/%s", sbomName), sbom).
		WithNewFile("/tmp/out/status.txt", errorString)
	return result_container.
		Directory("."), err
}
