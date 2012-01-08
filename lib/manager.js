/* */

/*
 * Copyright (c) 2011,2012 David Gwynne <david@gwynne.id.au>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

var assert = require('assert');
var dgram = require('dgram');
var Protocol = require('./protocol');

var SNMPMessage = require('./messages');

var OPT_TEMPLATE = {
	version: 1,
	community: 'public',

	af: 'inet4',
	localport: 0,
	port: 161,

	retries: 5,
	delay: 1000,

	/* bulk get bits */
	nonRepeaters: 0,
	maxRepetitions: 10
};

/* Helpers */

function merge(from, to) {
	assert.ok(from);
	assert.equal(typeof(from), 'object');
	assert.ok(to);
	assert.equal(typeof(to), 'object');

	var keys = Object.getOwnPropertyNames(from);
	keys.forEach(function(key) {
		if (to[key])
			return;

		var value = Object.getOwnPropertyDescriptor(from, key);
		Object.defineProperty(to, key, value);
	});

	return (to);
}

var af2dgram = {
	'inet4': 'udp4',
	'inet6': 'udp6'
};

var ver2wire = {
	1: Protocol.SNMPv1,
	2: Protocol.SNMPv2c
};

function cmpOIDPrefix(x, y)
{
	xa = x.split('.');
	ya = y.split('.');

	if (ya.length < xa.length)
		return (false);

	y = ya.slice(0, xa.length).join('.');

	return (x === y);
}

function parseBulkGet(options, varBindList, oids, rv)
{
	var done = true;

	for (var i = options.nonRepeaters; i < options.oids.length; i++) {
		var varBind = { oid: options.oids[i] };
		for (var j = 0; j < options.maxRepetitions; j++) {
			if (typeof(varBindList[i + j]) === 'undefined') {
				/*
				 * some agents *cough*cisco*cough* truncate the
				 * list if the packet gets too large
				 */
				done = false;
				break;
			}
			varBind = varBindList[i + j];

			if (!cmpOIDPrefix(options.oids[i], varBind.oid))
				break;

			rv.push(varBind);
			done = false;
		}
		oids.push(varBind.oid);
	}

	return (done);
}

function nextBulkGet(self, options, varBindList)
{
	var rv = [ ];
	var oids = [ ];

	for (var i = 0; i < options.nonRepeaters; i++) {
		oids.push(options.oids[i]);
		if (cmpOIDPrefix(options.oids[i], varBindList[i].oid))
			rv.push(varBindList[i]);
	}

	var done = parseBulkGet(options, varBindList, oids, rv);
	if (rv.length)
		options.cb(0, rv);
	if (done)
		return;

	var id;
	do {
		id = Math.floor(Math.random() * (1 << 30));
	} while (typeof(self._requests[id]) !== 'undefined');

	var ber = SNMPMessage.getBulkRequest({
		version: ver2wire[options.version],
		community: options.community,
		messageId: id,
		nonRepeaters: options.nonRepeaters,
		maxRepetitions: options.maxRepetitions,
		varBindList: oids.map(function (o) {
			return { oid: o, type: 'null' };
		})
	}).toBer();

	options.ber = ber;
	self._requests[id] = options;
	options.tries = 1;
	options.timeout = setTimeout(managerRetry, options.delay, self, id);

	self._dgram.send(ber.buffer, 0, ber.buffer.length,
	    options.port, options.agent);

}

function managerRetry(self, id)
{
	var request = self._requests[id];

	if (request.tries++ <= request.retries) {
		request.timeout = setTimeout(managerRetry, request.delay,
		    self, id);
		self._dgram.send(request.ber.buffer, 0,
		    request.ber.buffer.length, request.port, request.agent);
	} else {
		delete(self._requests[id]);
		request.cb(1, {});

		if (Object.keys(self._requests).length == 0)
			self._dgram.close();
	}
}

function managerRecv(self, buf, peer)
{
	var msg = SNMPMessage.parse(buf);
	var id = msg.messageId;

	if (typeof(self._requests[id]) === 'undefined')
		return;

	var options = self._requests[id];
	if (ver2wire[options.version] !== msg.version ||
	    options.community !== msg.community)
		return;

	clearTimeout(options.timeout);
	delete(self._requests[id]);

	switch (options.type) {
	case 'get':
		options.cb(msg.error, msg.varBindList);
		break;

	case 'bulkget':
		nextBulkGet(self, options, msg.varBindList);
		break;
	}

	if (Object.keys(self._requests).length == 0)
		self._dgram.close();
}

/* API */

function Manager(options)
{
	options = merge(OPT_TEMPLATE, options || {});

	if (typeof(af2dgram[options.af]) === 'undefined')
		throw new Error('invalid address family (af)');
	if (typeof(ver2wire[options.version]) === null)
		throw new Error('invalid SNMP version');

	this._options = options;
	this._requests = {};
	
	var self = this;
	this._dgram = dgram.createSocket(af2dgram[options.af]);
	this._dgram.on("message",
	    function (msg, peer) { managerRecv(self, msg, peer); });
	this._dgram.on("listening",
	    function () { /* XXX */ });
	this._dgram.on("error",
	    function (err) { /* XXX */ });

	this._dgram.bind(options.localport);
	process.nextTick(function() {
		if (Object.keys(self._requests).length == 0)
			self._dgram.close();
	});
}

Manager.prototype.get = function (agent, oids, cb, options)
{
	if (typeof(agent) !== 'string')
		throw new TypeError('agent (string) required');
	if (typeof(oids) === 'string')
		oids = [ oids ];
	else if (typeof(oids) !== 'object')
		throw new TypeError('oids (string/array[strings]) required');
	if (typeof(cb) !== 'function')
		throw new TypeError('callback (function) required');

	options = merge(this._options, options || {});
	if (typeof(ver2wire[options.version]) === 'undefined')
		throw new Error('invalid SNMP version');

	var id;
	do {
		id = Math.floor(Math.random() * (1 << 30));
	} while (typeof(this._requests[id]) !== 'undefined');

	var ber = SNMPMessage.getRequest({
		version: ver2wire[options.version],
		community: options.community,
		messageId: id,
		varBindList: oids.map(function (o) {
			return { oid: o, type: 'null' };
		})
	}).toBer();

	options.type = 'get';
	options.agent = agent;
	options.cb = cb;
	options.ber = ber;
	this._requests[id] = options;
	options.timeout = setTimeout(managerRetry, options.delay, this, id);

	this._dgram.send(ber.buffer, 0, ber.buffer.length, options.port, agent);
}

Manager.prototype.bulkGet = function (agent, oids, cb, options)
{
	if (typeof(agent) !== 'string')
		throw new TypeError('agent (string) required');
	if (typeof(oids) === 'string')
		oids = [ oids ];
	else if (typeof(oids) !== 'object')
		throw new TypeError('oids (string/array[strings]) required');
	if (typeof(cb) !== 'function')
		throw new TypeError('callback (function) required');

	options = merge(this._options, options || {});
	if (typeof(ver2wire[options.version]) === 'undefined' ||
	    ver2wire[options.version] !== Protocol.SNMPv2c)
		throw new Error('invalid SNMP version');
	if (oids.length < options.nonRepeaters)
		throw new Error('less oids than nonRepeaters');

	var id;
	do {
		id = Math.floor(Math.random() * (1 << 30));
	} while (typeof(this._requests[id]) !== 'undefined');

	var ber = SNMPMessage.getBulkRequest({
		version: ver2wire[options.version],
		community: options.community,
		messageId: id,
		nonRepeaters: options.nonRepeaters,
		maxRepetitions: options.maxRepetitions,
		varBindList: oids.map(function (o) {
			return { oid: o, type: 'null' };
		})
	}).toBer();

	options.type = 'bulkget';
	options.agent = agent;
	options.cb = cb;
	options.ber = ber;
	options.oids = oids.slice(0);
	this._requests[id] = options;
	options.tries = 1;
	options.timeout = setTimeout(managerRetry, options.delay, this, id);

	this._dgram.send(ber.buffer, 0, ber.buffer.length, options.port, agent);
}

module.exports = Manager;
