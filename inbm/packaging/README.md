# Building

## Acquire FPM

For a full reference, see https://fpm.readthedocs.io/en/latest/installing.html#installing-things-fpm-needs

On Ubuntu 20.04:

* `sudo apt install ruby ruby-dev rubygems build-essential`
* `sudo gem install public_suffix -v 5.1.1`
* `sudo gem install --no-document fpm -v 1.14.0`

### Set up jfrog

* Install go.
* Run: `go get github.com/jfrogdev/jfrog-cli-go/...`
* Create `$HOME/.jfrog/jfrog-cli.conf`:
```
{
  "artifactory": [
    {
      "url": "https://af01p-igk-app01.devtools.intel.com/artifactory/",
      "apiKey": "<PUT YOUR API KEY HERE>",
      "isDefault": true
    }
  ],
  "Version": "1"
}
```

* Ensure `jfrog-cli.conf` is secured.  On Linux, run `chmod og-rwx $HOME/.jfrog/jfrog-cli.conf`

### Fetch dependencies

* Place the `trtl` binary in `input/`
* Put `trtl.conf` in `input/`

### Build

* `make` (faster: `make -j16`)
* Output packages will appear in `output/`
