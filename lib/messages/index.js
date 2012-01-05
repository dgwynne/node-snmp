/* */

/*
 * Copyright (c) 2012 David Gwynne <david@gwynne.id.au>
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

var SNMPMessage = require ('./message');
var Protocol = require('../protocol');

function PDU(options)
{
	options.v1 = options.error;
	delete(options.error);
	options.v2 = options.errorOffset;
	delete(options.errorOffset);

	var self = new SNMPMessage(options);

	self.__defineGetter__('error',
	    function() { return (self.v1); });
	self.__defineGetter__('errorOffset',
	    function() { return (self.v2); });

	return (self);
}

function BulkPDU(options)
{
	options.PDU = Protocol.PDU_GetBulkRequest;

	options.v1 = options.nonRepeaters;
	delete(options.nonRepeaters);
	options.v2 = options.maxRepetitions;
	delete(options.maxRepetitions);

	var self = new SNMPMessage(options);

	self.__defineGetter__('nonRepeaters',
	    function() { return (self.v1); });
	self.__defineGetter__('maxRepetitions',
	    function() { return (self.v2); });

	return (self);
}

var PDUs = {
	getRequest: Protocol.PDU_GetRequest,
	getNextRequest: Protocol.PDU_GetNextRequest,
	getResponse: Protocol.PDU_GetResponse,
	setRequest: Protocol.PDU_SetRequest,
	trap: Protocol.PDU_Trap,
        // Protocol.PDU_GetBulkRequest,
	informRequest: Protocol.PDU_InformRequest,
	trapV2: Protocol.PDU_TrapV2,
	report: Protocol.PDU_Report
};

function exportPDU(k)
{
	return (function(options) {
		options.PDU = PDUs[k];
		return PDU(options);
	});
}

module.exports.getBulkRequest = BulkPDU;
for (var k in PDUs) {
	module.exports[k] = exportPDU(k);
}

module.exports.parse = function (buf)
{
	var msg = new SNMPMessage();
	msg.parse(buf);
	return (msg);
}
