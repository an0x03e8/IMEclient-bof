# IMEclient-bof

Set of BOFs to interact with Intune Company Portal for self-service installs directly from Beacon.

The project was inspired by a [blogpost](https://blog.amberwolf.com/blog/2026/october/company-portal-self-service-to-system/) written by Richard Warren/AmberWolf and the BOF tooling is largely based on the C# tool published along with it (see: [IMEClient](https://github.com/AmberWolfCyber/IMEClient)).

## Build

Requires `x86_64-w64-mingw32-gcc` and `boflink` ≥ 0.6.1 (override with
`make BOFLINK=/path/to/boflink`):

    make all

COFFs land in `dist/*.x64.o`. x64 beacons only.

## Usage

Load `ime.cna` (the aliases resolve `dist/*.x64.o` relative to it).
Then, from a beacon on a workplace-joined device:

    ime-token                                      # mint the enrollment token in-beacon -> KV 'imeToken' (+IW url)
    ime-auth                                       # store imeCtx: token/iwurl from the KV, device id from the MDM cert
    ime-list                                       # catalogue: #  GuidKey  Name  Publisher
    ime-install install <name-substring|#|guid>    # post action
    ime-checkin                                    # sync trigger


## License

[MIT](LICENSE)
