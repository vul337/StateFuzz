// AUTOGENERATED FILE

struct call_attrs_t { 
	uint64_t disabled;
	uint64_t timeout;
	uint64_t prog_timeout;
	uint64_t ignore_return;
	uint64_t breaks_returns;
};

#if GOOS_akaros
#define GOOS "akaros"

#if GOARCH_amd64
#define GOARCH "amd64"
#define SYZ_REVISION "8b8da1e1deaaf3563ed390a82d7662380a7b270d"
#define SYZ_EXECUTOR_USES_FORK_SERVER 1
#define SYZ_EXECUTOR_USES_SHMEM 0
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#endif

#if GOOS_freebsd
#define GOOS "freebsd"

#if GOARCH_386
#define GOARCH "386"
#define SYZ_REVISION "0093126d4fd30f57d63bd402970807dff02f27c1"
#define SYZ_EXECUTOR_USES_FORK_SERVER 1
#define SYZ_EXECUTOR_USES_SHMEM 1
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#if GOARCH_amd64
#define GOARCH "amd64"
#define SYZ_REVISION "e27461fb0766092e9df2202e8f717322a626dacf"
#define SYZ_EXECUTOR_USES_FORK_SERVER 1
#define SYZ_EXECUTOR_USES_SHMEM 1
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#endif

#if GOOS_fuchsia
#define GOOS "fuchsia"

#if GOARCH_amd64
#define GOARCH "amd64"
#define SYZ_REVISION "21632f7036852579f92528d5de753a854437891e"
#define SYZ_EXECUTOR_USES_FORK_SERVER 0
#define SYZ_EXECUTOR_USES_SHMEM 0
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#if GOARCH_arm64
#define GOARCH "arm64"
#define SYZ_REVISION "ed0973ad1861a690b488eeb1294556a5436d7476"
#define SYZ_EXECUTOR_USES_FORK_SERVER 0
#define SYZ_EXECUTOR_USES_SHMEM 0
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#endif

#if GOOS_linux
#define GOOS "linux"

#if GOARCH_386
#define GOARCH "386"
#define SYZ_REVISION "9bea90fee0bb1a157b9f5951fd83ff2e79e7c4ed"
#define SYZ_EXECUTOR_USES_FORK_SERVER 1
#define SYZ_EXECUTOR_USES_SHMEM 1
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#if GOARCH_amd64
#define GOARCH "amd64"
#define SYZ_REVISION "73ffe418db00e29db0840d761d48a14bd4883a3b"
#define SYZ_EXECUTOR_USES_FORK_SERVER 1
#define SYZ_EXECUTOR_USES_SHMEM 1
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#if GOARCH_arm
#define GOARCH "arm"
#define SYZ_REVISION "3fe794cd580dffc956009a9fba3efd350b04ce62"
#define SYZ_EXECUTOR_USES_FORK_SERVER 1
#define SYZ_EXECUTOR_USES_SHMEM 1
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#if GOARCH_arm64
#define GOARCH "arm64"
#define SYZ_REVISION "cff73bb937f99aaa6e2c5cdb3be0cc23334a0172"
#define SYZ_EXECUTOR_USES_FORK_SERVER 1
#define SYZ_EXECUTOR_USES_SHMEM 1
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#if GOARCH_mips64le
#define GOARCH "mips64le"
#define SYZ_REVISION "ce1346bce6ce8446d31038027bdaf28fb0a57f22"
#define SYZ_EXECUTOR_USES_FORK_SERVER 1
#define SYZ_EXECUTOR_USES_SHMEM 1
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#if GOARCH_ppc64le
#define GOARCH "ppc64le"
#define SYZ_REVISION "513d1b72273b94960ed37328e7b6f0cf24026c72"
#define SYZ_EXECUTOR_USES_FORK_SERVER 1
#define SYZ_EXECUTOR_USES_SHMEM 1
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#endif

#if GOOS_netbsd
#define GOOS "netbsd"

#if GOARCH_amd64
#define GOARCH "amd64"
#define SYZ_REVISION "cfade73149be849328125311c83788accf9be244"
#define SYZ_EXECUTOR_USES_FORK_SERVER 1
#define SYZ_EXECUTOR_USES_SHMEM 1
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#endif

#if GOOS_openbsd
#define GOOS "openbsd"

#if GOARCH_amd64
#define GOARCH "amd64"
#define SYZ_REVISION "75b6763323587f0c0394d5d50633ec9edd8b0538"
#define SYZ_EXECUTOR_USES_FORK_SERVER 1
#define SYZ_EXECUTOR_USES_SHMEM 1
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#endif

#if GOOS_test
#define GOOS "test"

#if GOARCH_32_fork_shmem
#define GOARCH "32_fork_shmem"
#define SYZ_REVISION "456a214c4756bcc6f35068f49d66e0bd0fc148ea"
#define SYZ_EXECUTOR_USES_FORK_SERVER 1
#define SYZ_EXECUTOR_USES_SHMEM 1
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#if GOARCH_32_shmem
#define GOARCH "32_shmem"
#define SYZ_REVISION "4c7b394ba6582ba2de8ec69e0e14a256167df5c5"
#define SYZ_EXECUTOR_USES_FORK_SERVER 0
#define SYZ_EXECUTOR_USES_SHMEM 1
#define SYZ_PAGE_SIZE 8192
#define SYZ_NUM_PAGES 2048
#define SYZ_DATA_OFFSET 536870912
#endif

#if GOARCH_64
#define GOARCH "64"
#define SYZ_REVISION "1b0d150488cefe6deefd19eac3964e1ec6cc947b"
#define SYZ_EXECUTOR_USES_FORK_SERVER 0
#define SYZ_EXECUTOR_USES_SHMEM 0
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#if GOARCH_64_fork
#define GOARCH "64_fork"
#define SYZ_REVISION "17ac79e508e188420ae3b72436f9d8e66c4cec48"
#define SYZ_EXECUTOR_USES_FORK_SERVER 1
#define SYZ_EXECUTOR_USES_SHMEM 0
#define SYZ_PAGE_SIZE 8192
#define SYZ_NUM_PAGES 2048
#define SYZ_DATA_OFFSET 536870912
#endif

#endif

#if GOOS_trusty
#define GOOS "trusty"

#if GOARCH_arm
#define GOARCH "arm"
#define SYZ_REVISION "1363e8972f80b2905f34f95d1481d43a4b2ffbf6"
#define SYZ_EXECUTOR_USES_FORK_SERVER 0
#define SYZ_EXECUTOR_USES_SHMEM 0
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#endif

#if GOOS_windows
#define GOOS "windows"

#if GOARCH_amd64
#define GOARCH "amd64"
#define SYZ_REVISION "d588a33c19130b403f4cbc6a58d1f7c4af8c0987"
#define SYZ_EXECUTOR_USES_FORK_SERVER 0
#define SYZ_EXECUTOR_USES_SHMEM 0
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#endif

