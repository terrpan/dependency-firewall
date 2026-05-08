package npm

import "strings"

// parsePackagePath extracts package name and optional version from the URL path.
//
//   - "@scope/name/version" -> name="@scope/name", version="version"
//   - "@scope/name"         -> name="@scope/name", version=""
//   - "name/version"        -> name="name",        version="version"
//   - "name"                -> name="name",        version=""
func parsePackagePath(path string) (name, version string) {
	if strings.HasPrefix(path, "@") {
		parts := strings.SplitN(path, "/", 3)
		if len(parts) < 2 {
			return path, ""
		}
		name = parts[0] + "/" + parts[1]
		if len(parts) == 3 && parts[2] != "" {
			version = parts[2]
		}
		return name, version
	}

	name, version, _ = strings.Cut(path, "/")
	return name, version
}

// parseTarballPath detects and parses tarball download URLs.
//
// Pattern: {@scope/name|-}/name-version.tgz -> (fullName, version)
func parseTarballPath(path string) (name, version string, ok bool) {
	before, after, ok0 := strings.Cut(path, "/-/")
	if !ok0 {
		return "", "", false
	}

	name = before
	filename := after
	if !strings.HasSuffix(filename, ".tgz") {
		return "", "", false
	}
	filename = strings.TrimSuffix(filename, ".tgz")

	basename := name
	if slashIdx := strings.LastIndex(name, "/"); slashIdx >= 0 {
		basename = name[slashIdx+1:]
	}

	prefix := basename + "-"
	if !strings.HasPrefix(filename, prefix) {
		return "", "", false
	}
	version = filename[len(prefix):]
	if version == "" {
		return "", "", false
	}

	return name, version, true
}

func tarballFilename(name, version string) string {
	basename := name
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		basename = name[idx+1:]
	}
	return name + "/-/" + basename + "-" + version + ".tgz"
}
