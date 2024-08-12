const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const { PubSub } = require('@google-cloud/pubsub');

const app = express();
const port = 8080;


app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());


const pubsubTopic = "vulnerability_report";


const pubSubClient = new PubSub();

// ROUTES
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '/public/index.html'));
});

app.post('/subscribe', async (req, res) => {
    const email = req.body.email_address;
    const assetName = req.body.asset_name;

    try {
        const messageData = JSON.stringify({
            email_address: email,
            assetName: assetName
        });

        // Create a data buffer that allows us to stream the message to the topic
        const dataBuffer = Buffer.from(messageData);

        // Publish the message to the PubSub topic
        const messageId = await pubSubClient.topic(pubsubTopic).publishMessage({ data: dataBuffer });

        console.log(`Message published with ID: ${messageId}`);

        res.status(200).send(`Thanks for subscribing to receive vulnerability reports for ${assetName}.`);
    } catch (error) {
        console.error('Error publishing message to Pub/Sub topic:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.listen(port, () => {
    console.log(`Vulnerability Reports Web App listening on port ${port}`);
});
