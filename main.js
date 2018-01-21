const nsort = require('javascript-natural-sort');
const minimist = require('minimist');
const pcap = require('pcap-parser');
const esc = require('ansi-escapes');
const chalk = require('chalk');
const fs = require('fs');

console.log(chalk.blue('# Welcome to the SVSi analyser.'));

var args = minimist(process.argv.slice(2), {
  boolean: [ 'verbose' ],
  alias: { v: 'verbose' }
})

var file = args._[0];

if(!file) {
  console.log(chalk.red('> Please provide a .pcap file to analyse.'));
  return;
}

if(!fs.existsSync(file)) {
  console.log(chalk.red('> The specified file could not be found.'));
  return;
}

process.stdout.write("\n");
process.stdout.write(esc.cursorSavePosition);

console.log(chalk.blue('Loading PCAP file...\n'));

var parser = pcap.parse(file);

const multicastHeader = new Buffer([0x01, 0x00, 0x5e]);

var streams = {};

var V = args.verbose ? 3 : 0; // verbosity

var pcount = 0;

// Parser
parser.on('packet', function(packet) {

  pcount++;

  // Ignore packets destined for non-multicast dest MACs
  if(packet.data.slice(0,3).compare(multicastHeader) != 0) { return; }

  // Find offsets
  var ipOffset = 14; // Ethernet headers always 14 bytes, right?
  var ipLength = (packet.data[ipOffset] & 0xf) * 4;
  var udpOffset = (ipOffset + ipLength + 8);

  if(packet.data.slice(udpOffset+2, udpOffset+6).toString() != 'SVSI') {
    return; // Not an SVSI stream
  }

  var ip = packet.data.slice(30,34);
  if(!streams[ip]) {
    streams[ip] = {
      friendly: ip[0] + '.' + ip[1] + '.' + ip[2] + '.' + ip[3],
      ok: 0,
      miss: 0,
      dup: 0,
      late: 0
    };
  }

  var rollingByte = packet.data[udpOffset+9];
  if(rollingByte === undefined) {
    console.log(chalk.red('!!! Capture snap length too short !!!'));
    process.exit();
  }

  if(streams[ip].lastRollingByte) {
    var diff = rollingByte - streams[ip].lastRollingByte;
    if(diff < 0) { diff += 256; }
    if(V > 4) { console.log(chalk.blue("> OK")); }
    if(diff > 1) {
      streams[ip].miss++;
      if(V > 2) { debug(chalk.red("> Missed chunk between packets " + streams[ip].lastRollingByte + " and " + rollingByte + " in stream " + streams[ip].friendly)); }
    } else if(diff == 0) {
      streams[ip].dup++;
      if(V > 3) { debug(chalk.red("> Duplicate packet " + rollingByte + " in stream " + streams[ip].friendly)); }
    } else if(diff < 0) {
      streams[ip].late++;
      if(V > 3) { debug(chalk.red("> Out of order packet " + rollingByte + " after " + streams[ip].lastRollingByte + " in stream " + streams[ip].friendly)); }
    }
  }

  streams[ip].lastRollingByte = rollingByte;

});

function debug(str) {
  process.stdout.write(esc.cursorUp(2));
  process.stdout.write(esc.eraseDown);
  console.log(str + '\n\n');
}

// Done
parser.on('end', function (persist) {

  process.stdout.write('\n');
  //process.stdout.write(esc.cursorUp(2));

  var printable = [];
  for(var i in streams) {
    var prob = streams[i].miss > 0 || streams[i].dup > 0 || streams[i].late > 0;
    var info = chalk[prob?'red':'green']("> " + streams[i].friendly + " " + (!prob ? "OK" : "(" + (streams[i].miss + " missing, " + streams[i].late + " late, " + streams[i].dup + " duplicates)")));
    printable.push(info);
  }

  // Natural sort
  printable = printable.sort(nsort);

  console.log(printable.join("\n"));

  process.exit();

});

// Progress update
setInterval(function() {

  var summary = {
    cnt: 0, broken: 0, miss: 0, dup: 0, late: 0
  };

  for(var i in streams) {
    var prob = streams[i].miss > 0 || streams[i].dup > 0 || streams[i].late > 0;
    summary.cnt++;
    if(prob) { summary.broken++; }
    summary.miss += streams[i].miss;
    summary.dup += streams[i].dup;
    summary.late += streams[i].late;
  }

  process.stdout.write(esc.cursorUp(2));
  console.log("Processing: " + pcount + " packets.")
  console.log("Streams: " + summary.cnt + (summary.broken < 1 ? ' OK' : ', '+chalk.red(summary.broken + ' broken streams (' + summary.miss + ' missing, ' + summary.late + ' late, ' + summary.dup + ' duplicates)')))

}, 500);