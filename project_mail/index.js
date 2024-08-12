const { Mailsending } = require('./1.js');
const { WriteToBigQuery } = require('./2.js');

exports.proj = (message, context) => {
    Mailsending(message, context);
    WriteToBigQuery(message, context);
}
