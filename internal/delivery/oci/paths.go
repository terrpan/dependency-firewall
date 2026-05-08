package oci

import "strings"

// parseManifestPath extracts repository and reference from a path like
// "library/nginx/manifests/latest".
func parseManifestPath(path string) (repo, reference string, ok bool) {
	const marker = "/manifests/"
	idx := strings.LastIndex(path, marker)
	if idx < 0 {
		return "", "", false
	}
	repo = path[:idx]
	reference = path[idx+len(marker):]
	if repo == "" || reference == "" {
		return "", "", false
	}
	return repo, reference, true
}

// parseBlobPath extracts repository and digest from a path like
// "library/nginx/blobs/sha256:abc123".
func parseBlobPath(path string) (repo, digest string, ok bool) {
	const marker = "/blobs/"
	idx := strings.LastIndex(path, marker)
	if idx < 0 {
		return "", "", false
	}
	repo = path[:idx]
	digest = path[idx+len(marker):]
	if repo == "" || digest == "" {
		return "", "", false
	}
	return repo, digest, true
}

// splitRepo splits a repository path into namespace and name.
// For "library/nginx" -> ("library", "nginx").
// For "nginx" -> ("", "nginx").
// For "a/b/c" -> ("a/b", "c").
func splitRepo(repo string) (namespace, name string) {
	idx := strings.LastIndex(repo, "/")
	if idx < 0 {
		return "", repo
	}
	return repo[:idx], repo[idx+1:]
}
