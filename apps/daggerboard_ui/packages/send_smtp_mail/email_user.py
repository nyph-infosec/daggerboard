import logging
import pathlib
import smtplib
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def send_email(  # noqa: C901
    subject,
    sender,
    receivers,
    text,
    host,
    port,
    reply_to=None,
    html=None,
    cc=None,
    bcc=None,
    attachment=None,
):
    """Sends Email using an SMTP Server"""
    # Validate Arguments as a list
    if "list" not in str(type(receivers)):
        logging.info("Receivers not provided in list form")
        raise ValueError("Receivers parameter is expecting an array")
    # Prepare email
    subject = subject
    # Create a multipart message and set headers
    message = MIMEMultipart("alternative")
    message["From"] = reply_to
    message["To"] = " ,".join(receivers)
    message["Subject"] = subject
    message["reply-to"] = reply_to
    # if there are cc recipients, check if its a list and if it is continue
    if cc is not None:
        if "list" not in str(type(cc)):
            logging.info("Receivers not provided in list form")
            raise ValueError("CC parameter is expecting an array")
        else:
            message["Cc"] = " ,".join(cc)
            receivers = receivers + cc
    # if there are bcc recipients, check if its a list and if it is continue
    if bcc is not None:
        if "list" not in str(type(bcc)):
            logging.info("Receivers not provided in list form")
            raise ValueError("BCC parameter is expecting an array")
        else:
            message["Bcc"] = " ,".join(bcc)
            receivers = receivers + bcc
    # message["Bcc"] = bcc_email  # Recommended for mass emails need to work on this piece
    # Turn these into plain/html MIMEText objects
    part1 = MIMEText(text, "plain")
    # Add HTML/plain-text parts to MIMEMultipart message
    # The email client will try to render the last part first
    message.attach(part1)
    if html is not None:
        part2 = MIMEText(html, "html")
        message.attach(part2)
    # attach attachment if provided
    if attachment is not None:
        attachpath = pathlib.Path(attachment)
        if attachpath.is_file():
            # Filenams/location
            fileloc = attachpath
            filename = attachpath.name
            # Open PDF file in binary mode
            with open(fileloc, "rb") as attachment:
                # Add file as application/octet-stream
                # Email client can usually download this automatically as attachment
                part = MIMEBase("application", "octet-stream")
                part.set_payload(attachment.read())
            # Encode file in ASCII characters to send by email
            encoders.encode_base64(part)
            # Add header as key/value pair to attachment part
            part.add_header(
                "Content-Disposition",
                f"attachment; filename= {filename}",
            )
            # Add attachment to message and convert message to string
            message.attach(part)
        else:
            logging.error(
                "Please make sure the attachment is the full location path for the attachment"
            )
            raise ValueError("The attachment parameter requires a valid path")
    # Set Email
    text = message.as_string()
    # set SMTP settings and send email
    try:
        with smtplib.SMTP(host, port) as server:
            send = server.sendmail(sender, receivers, text)
            return len(send)
    except Exception as e:
        logging.error(e)
        raise
