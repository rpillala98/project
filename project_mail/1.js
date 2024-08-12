const sgMail = require('@sendgrid/mail');
const { Storage } = require('@google-cloud/storage');
const { Firestore } = require('@google-cloud/firestore');
const csv = require('csv-parser');
const fs = require('fs');
const path = require('path');

const storage = new Storage();

exports.Mailsending = async (message, context) => {
    try {

        const initialBucketName = 'gs://initialbucket_2';
        const reportBucketName = 'gs://vulnerability_report';
        const reportFileName = 'vulnerability_report.csv';

        async function copyFileAndDelete(sourceBucketName, sourceFilename, destBucketName, destFilename) {
            await storage.bucket(sourceBucketName).file(sourceFilename).copy(storage.bucket(destBucketName).file(destFilename));
            await storage.bucket(sourceBucketName).file(sourceFilename).delete();
            console.log(`File ${sourceFilename} copied to ${destBucketName} as ${destFilename} and deleted from ${sourceBucketName}.`);
        }
        const [initialFiles] = await storage.bucket(initialBucketName).getFiles();
        for (const file of initialFiles) {
            const sourceFilename = file.name;
            if (sourceFilename !== reportFileName) {
                await copyFileAndDelete(initialBucketName, sourceFilename, reportBucketName, reportFileName);
            }
        }

        sgMail.setApiKey(process.env.SENDGRID_API_KEY);

        const reportData = JSON.parse(Buffer.from(message.data, 'base64').toString());

        const firestore = new Firestore();

        const usersSnapshot = await firestore.collection('Vulnerability_subscribers').where('assetName', '==', reportData.assetName).get();
        const subscriberEmails = usersSnapshot.docs.map(doc => doc.data().email_address);
        const subscriberDocs = usersSnapshot.docs.map(doc => doc.ref);

        const bucketName = reportBucketName;
        const [files] = await storage.bucket(bucketName).getFiles();

        if (files.length === 0) {
            console.warn('No report file found in the bucket.');
            return;
        }

        
        const fileName = files[0].name;
        const file = storage.bucket(bucketName).file(fileName);
        const activeNewVulnerabilities = [];
        const fixedVulnerabilities = [];

        await new Promise((resolve, reject) => {
            file.createReadStream()
                .pipe(csv())
                .on('data', (row) => {
                    if (row.DNS === reportData.assetName) {
                        if (row['Vuln Status'] === 'Active' || row['Vuln Status'] === 'New') {
                            activeNewVulnerabilities.push(row);
                        } else if (row['Vuln Status'] === 'Fixed') {
                            fixedVulnerabilities.push(row);
                        }
                    }
                })
                .on('end', () => {
                    console.log('CSV file reading completed.');
                    console.log('activeNewVulnerabilities:', activeNewVulnerabilities);
                    console.log('fixedVulnerabilities:', fixedVulnerabilities);
                    resolve();
                })
                .on('error', (error) => {
                    console.error('Error reading CSV file:', error);
                    reject(error);
                });
        });

        if (activeNewVulnerabilities.length === 0 && fixedVulnerabilities.length === 0) {
            console.warn('No data found in CSV file for asset: ', reportData.assetName);
            return;
        }

        const activeNewCSVData = formatCSVData(activeNewVulnerabilities);
        const fixedCSVData = formatCSVData(fixedVulnerabilities);

        const activeNewCSVFilePath = path.join('/tmp', 'active_new_vulnerability_report.csv');
        const fixedCSVFilePath = path.join('/tmp', 'fixed_vulnerability_report.csv');

        fs.writeFileSync(activeNewCSVFilePath, activeNewCSVData);
        fs.writeFileSync(fixedCSVFilePath, fixedCSVData);

        const filteredactiveNewCSV = fs.readFileSync(activeNewCSVFilePath, 'utf8');
        console.log('Filtered active new CSV data:', filteredactiveNewCSV);
        const filteredfixedCSV = fs.readFileSync(fixedCSVFilePath, 'utf8');
        console.log('Filtered fixed CSV data:', filteredfixedCSV);

        subscriberEmails.forEach(async (email) => {
            const senderEmail = process.env.SENDGRID_SENDER;
            const senderUsername = email.split('@')[0];
            try {
                await sgMail.send({
                    to: email,
                    from: senderEmail,
                    subject: 'Vulnerability Report for Your Asset',
                    text: `Dear ${senderUsername}, \n\nPlease find attached the vulnerability report for your asset.\n\nRegards,\nYour Security Team`,
                    attachments: [
                        {
                            content: fs.readFileSync(activeNewCSVFilePath, { encoding: 'base64' }),
                            filename: 'active_new_vulnerability_report.csv',
                            type: 'text/csv',
                            disposition: 'attachment',
                        },
                        {
                            content: fs.readFileSync(fixedCSVFilePath, { encoding: 'base64' }),
                            filename: 'fixed_vulnerability_report.csv',
                            type: 'text/csv',
                            disposition: 'attachment',
                        },
                    ],
                });
                console.log(`Email sent successfully to ${email}`);
            } catch (error) {
                console.error(`Error sending email to ${email}:`, error);
            }
        });
        Promise.all(subscriberDocs.map(doc => doc.delete()));
    } catch (error) {
        console.error('Error sending email reports:', error);
    }
};

function formatCSVData(data) {
    if (data.length === 0) {
        return '';
    }

    const headers = Object.keys(data[0]).join(',');
    const rows = data.map(row => Object.values(row).map(value => value === null ? 'NULL' : `"${value.replace(/"/g, '""')}"`).join(',')).join('\n');
    return `${headers}\n${rows}`;
}