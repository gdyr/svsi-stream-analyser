# SVSi Stream Analyser

NodeJS-based PCAP analyser that looks for discontinuities in SVSi audio streams.


### Features
- Live output summary of OK / broken streams.
- Displays per-stream gap counts (+ out of order IDs and duplicate IDs) at exit.
- Can be fed live data via named pipe.

### Installation
1. [Install](https://nodejs.org/en/) the NodeJS runtime
2. [Download](https://github.com/gmichael225/svsi-stream-analyser/archive/master.zip) this GitHub repository
3. Unzip the archive, and run `npm install` within it.

### Usage
`node main.js myfile.pcap`, or

`node main.js -v myfile.pcap` for verbose output.