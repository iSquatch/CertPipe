# CertPipe

A CertStream monitoring tool. Monitor and alert on Certificate Transparency logs by looking for keyword matches. 

This is a customizable domain discovery, recon, and security tool based on Certificate Transparency log monitoring.

## Usage

### Basic Configuration

To get started, basic CertPipe configuration involves specifying keywords to search for (or ignore).  Edit the `config.py` file using a text editor to modify the configuration.

Here are the keyword settings in `config.py`:

![Example Screenshot of Keyword Configuration](https://github.com/iSquatch/CertPipe/blob/master/images/certpipe_example_config_screenshot_1.png)

### Run with Python

1. Install python dependencies with `pip install -r requirements`.
2. Edit `config.py` to configure the application.
3. Run the application using `python certpipe.py`

### Run in Docker

Easily create and run a CertPipe Docker image:

1. Edit `config.py` to configure the application.
2. Build the image using `docker build -t certpipe-docker .` within the CertPipe directory.
3. Start the Docker container in headless mode with `docker run -d certpipe-docker`.

### Output

Results can be viewed in a few ways:

- Slack or Mattermost alerting. Useful for receiving alerts on mobile device.
- CSV output (certpipe_matches.csv)
- Text output in terminal window
- URLScan.io scan results for matched domains

#### Example Text Output

![Example Screenshot of Text Output](https://github.com/iSquatch/CertPipe/blob/master/images/certpipe_example_screenshot_1.png)


## TODO:

- [x] List of keywords to alert on
- [x] List of keywords to always ignore
- [x] Use text similarity matching algorithms / Text Fuzzing
- [x] Create a configuration file
- [x] Text output
- [x] Basic Logging / Debug
- [x] Add Docker deployment option
- [x] Slack alerting
- [x] Mattermost Webhook alerting
- [x] CSV file output
- [x] Output type: matched domains
- [x] Scan the domains that match the keywords (URLScan.io Submission API)
- [x] Bulk send alert notifications every n seconds
- [ ] Output type: full detailed JSON
- [ ] Syslog output
- [ ] CLI argument handling for configuration
- [ ] Improve exception handling
- [ ] Lightweight web frontend for viewing live results
