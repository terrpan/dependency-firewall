package buildinfo

import "runtime/debug"

// Info holds build metadata.
type Info struct {
	Version   string
	Commit    string
	BuildTime string
}

// Read returns build metadata from embedded build info with ldflags fallbacks.
func Read(fallbackVersion, fallbackCommit, fallbackBuildTime string) Info {
	info := Info{
		Version:   fallbackVersion,
		Commit:    fallbackCommit,
		BuildTime: fallbackBuildTime,
	}

	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		return info
	}

	if buildInfo.Main.Version != "" && buildInfo.Main.Version != "(devel)" {
		info.Version = buildInfo.Main.Version
	}

	for _, setting := range buildInfo.Settings {
		switch setting.Key {
		case "vcs.revision":
			info.Commit = setting.Value
		case "vcs.time":
			info.BuildTime = setting.Value
		case "vcs.modified":
			if setting.Value == "true" {
				info.Commit += "-dirty"
			}
		}
	}

	return info
}
