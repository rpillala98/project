# Vulnerability Reporting System 

## Overview

The Vulnerability Reporting System is a comprehensive solution designed to streamline vulnerability management and communication processes. Leveraging Google Cloud Platform (GCP) resources and SendGrid, the system automates vulnerability scanning, generates personalized reports, and provides real-time data visualization for stakeholders.

### Getting Started
#### Prerequisites
Before getting started, ensure you have the following prerequisites installed and set up:

**Google Cloud Platform (GCP) Account**: You'll need a GCP account with necessary permissions to deploy cloud functions, utilize GCP resources, and access services like Firestore, BigQuery, and Looker Studio.

**Qualys Account setup**: Obtain access to Qualys platform for vulnerability scanning and report generation.
1. Create a Qualys account using a business email.
2. Choose the **Cloud Agent** module from **Sensor Management** for vulnerability scanning.
3. Install Qualys Cloud Agents on target machines following the guidelines provided [here](https://docs.qualys.com/en/csam/latest/inventory/sensors/cloud_agent.htm).

-Note: Installation procedures may vary based on the operating system used.

**Generating Vulnerability Report**:
1. After installing agents on target machines, access the Qualys console.
2. Start an on-demand scan either through ad-hoc means or scheduling.
3. Once the scan is completed, navigate to the **VMDR** module under **Infrastructure Security**.
4. Choose **`Report`** to create a vulnerability report using a template.
5. Select the technical report template and identify the asset for which the report is generated as the report source.
6. Download the generated report and upload it to the **initialbucket_2** in Google Cloud Storage.


**SendGrid Account**: Sign up for a SendGrid account to enable email notifications and communication with subscribers.
Please make sure to create an account with SendGrid, create an API key which is to be used for sending mails.
Also, include the environment variables such as **`SENDGRID_API_KEY`** and **`SENDGRID_SENDER`** to be includeed in cloud function created in order to receive mails from that sender.

#### Project Setup
**1. Clone the Repository**: Clone the project repository from Git to your local machine.

```bash
git clone https://github.com/rpillala98/Final_Project_41200
```

**2. Navigate to Project Directories**:
- **`project_mail`**: Navigate to the **`project_mail`** directory to deploy the cloud functions.

```bash
cd project_mail
```

- **`web`**: Navigate to the **`web directory`** under **`project_mail`** directory to run the web application.

```bash
cd web
```

**3. Install Dependencies**:
- In the **`project_mail`** directory, ensure you have Node.js installed, and install the necessary dependencies using npm.

```bash
npm install @sendgrid/mail @google-cloud/storage @google-cloud/firestore @google-cloud/bigquery csv-parser fs path
```

- Similarly, in the **`web directory`**, install required dependencies for the web application.
```bash
npm install express path @google-cloud/pubsub body-parser
```

**4. Set Up Environment Variables**:
Set up environment variables for necessary credentials and API keys required for GCP, and SendGrid. Refer to respective documentation for obtaining and configuring these credentials.

**5. Deploy Cloud Functions**:
Deploy the cloud functions from the **`project_mail`** directory using the provided command.
```bash
gcloud functions deploy VRS --runtime nodejs18 --trigger-topic vulnerability_report --entry-point Main --no-gen2
```

**6. Run Web Application**:
Run the web application from the **`web`** directory using Node.js.

```bash
node app.js
```

**7. Access Vulnerability Reports**:
- From the GCP console, click on "Web Preview" and preview on port 8080.
- Fill out the subscription form with your email address and asset name to subscribe and receive vulnerability reports.

**8. Monitor Vulnerability Trends**:
- Access Looker Studio by navigating to the Looker Studio platform in your GCP console. 
- Explore the visualized vulnerability data and trends for informed decision-making.
- Visualization for this project can be found from [here](https://lookerstudio.google.com/reporting/98c46503-e89b-40ae-bd9c-45cc127af4b8/page/p3TyD).