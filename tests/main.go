package main

import (
	"context"
	"dagger/tests/internal/dagger"
	"fmt"
	"time"

	"github.com/sourcegraph/conc/pool"
)

type Tests struct{}

// All executes all tests.
func (m *Tests) All(ctx context.Context) error {
	p := pool.New().WithErrors().WithContext(ctx)

	p.Go(m.Sbom)
	p.Go(m.SbomBuild)
	p.Go(m.Vulnscan)
	p.Go(m.Publish)
	p.Go(m.PublishWithCredentials)
	p.Go(m.Run)

	return p.Wait()
}

func (m *Tests) Sbom(_ context.Context) error {
	container := m.uniqContainer("alpine:latest", fmt.Sprintf("%d", time.Now().UnixNano()))
	if nil == dag.PitcFlow().Sbom(container) {
		return fmt.Errorf("should return sbom")
	}
	return nil
}

func (m *Tests) SbomBuild(_ context.Context) error {
	directory := dag.CurrentModule().Source().Directory("./testdata")
	if nil == dag.PitcFlow().SbomBuild(directory) {
		return fmt.Errorf("should build from dockerfile and return sbom")
	}
	return nil
}

func (m *Tests) Vulnscan(_ context.Context) error {
	container := m.uniqContainer("alpine:latest", fmt.Sprintf("%d", time.Now().UnixNano()))
	sbom := dag.PitcFlow().Sbom(container)
	if nil == dag.PitcFlow().Vulnscan(sbom) {
		return fmt.Errorf("should return vulnerabilty scan report")
	}
	return nil
}

func (m *Tests) Publish(ctx context.Context) error {
	container := m.uniqContainer("alpine:latest", fmt.Sprintf("%d", time.Now().UnixNano()))
	_, err := dag.PitcFlow().Publish(ctx, container, "ttl.sh/test/alpine:latest")
	if err != nil {
		return fmt.Errorf("should publish container to registry")
	}
	return nil
}

func (m *Tests) PublishWithCredentials(ctx context.Context) error {
	container := m.uniqContainer("alpine:latest", fmt.Sprintf("%d", time.Now().UnixNano()))
	secret := dag.SetSecret("password", "verySecret")
	_, err := dag.PitcFlow().Publish(
		ctx,
		container,
		"ttl.sh/test/alpine:latest",
		dagger.PitcFlowPublishOpts{RegistryUsername: "joe", RegistryPassword: secret},
	)
	if err != nil {
		return fmt.Errorf("should publish container to registry")
	}
	return nil
}

func (m *Tests) Run(ctx context.Context) error {
	lintContainer := m.uniqContainer("alpine:latest", fmt.Sprintf("%d", time.Now().UnixNano())).
		WithExec([]string{"sh", "-c", "echo 'lint' > /tmp/lint.txt"})
	sastContainer := m.uniqContainer("alpine:latest", fmt.Sprintf("%d", time.Now().UnixNano())).
		WithExec([]string{"sh", "-c", "echo 'sast' > /tmp/sast.txt"})
	testContainer := m.uniqContainer("alpine:latest", fmt.Sprintf("%d", time.Now().UnixNano())).
		WithExec([]string{"sh", "-c", "mkdir -p /tmp/tests"})

	dir := dag.CurrentModule().Source().Directory("./testdata")
	lintReport := "/tmp/lint.txt"
	sastReport := "/tmp/sast.txt"
	testReportDir := "/tmp/tests"
	registryUsername := "joe"
	secret := dag.SetSecret("password", "verySecret")
	registryAddress := "ttl.sh/test/alpine:latest"
	dtAddress := "ttl.sh"
	dtProjectUUID := "12345678-1234-1234-1234-123456789012"

	results := dag.PitcFlow().Run(
		dir,
		lintContainer,
		lintReport,
		sastContainer,
		sastReport,
		testContainer,
		testReportDir,
		registryUsername,
		secret,
		registryAddress,
		dtAddress,
		dtProjectUUID,
		secret,
	)

	if results == nil {
		return fmt.Errorf("should run the pipeline and return a results struct")
	}

	testReportsDir := results.TestReports()
	_, err := testReportsDir.Entries(ctx)
	if err != nil {
		return fmt.Errorf("should have returned some test reports")
	}

	success, err := results.Success(ctx)
	if !success || err != nil {
		return fmt.Errorf("should have run successfuly")
	}

	return nil
}

func (m *Tests) uniqContainer(image string, randomString string) *dagger.Container {
	return dag.Container().From(image).
		WithNewFile(
			fmt.Sprintf("/usr/share/%s", randomString),
			randomString,
		)
}
