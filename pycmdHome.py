#!/usr/bin/env python

'''
pycmdHome v1.0

@author: ghimire
@license: GPL v2.0

pycmdHome is a nifty little program that waits and listens for commands
through email. The command is executed with current user permission and
a reply is sent to the email sender.

Features:
* Sender Whitelist
* Subject Check
* Command Pattern Check
* Decode base64 emails.

Note: All emails are deleted right after they are checked.
'''

import sys, re, poplib, smtplib, email, subprocess, time, base64, cgi

UNDERLINE = ''
RED = '\x1b[1m\x1b[31m'
GREEN = '\x1b[1m\x1b[32m'
BLUE = '\x1b[1m\x1b[34m'
CYAN = '\x1b[1m\x1b[36m'
BLACK = '\x1b[1m\x1b[30m'
YELLOW = '\x1b[1m\x1b[33m'
WHITE = '\x1b[1m\x1b[37m'
GREENB = '\x1b[42'
YELLOWB = '\x1b[43m'
BLUEB = '\x1b[44m'
MAGENTAB = '\x1b[45m'
ENDC = '\x1b[0m'

# POP information to check and listen for commands
POPSERVER = 'example.org'
POPUSER = 'user@exmaple.org'
POPPASS = 's0m3s3cre7'
LOGFILE = 'log.txt'

# SMTP information to send a reply
SMTPAUTH = 0;
SMTPUSER = POPUSER
SMTPPASS = POPPASS
SMTPSERVER = 'example.org:25'
SENDERADDRESS = POPUSER
SENDERNAME = 'pycmdHome Reply'
SENDSUBJECT = 'Command Return'

# Regular expression to match the sender
# Leave it empty to match all addresses
sender_whitelist = ["myemail@example.org"]

# 0-Disable 1-Enable Subject check
SUBJECT_CHECK_ENABLED = 1
# Regular expression to match the subject
SUBJECT_MATCH = r"^(.*)$"
# SUBJECT_MATCH = r"^(This should match)$"

# Email check interval in seconds
EMAIL_CHECK_DELAY = 10

# 0-Disable 1-Enable mail check message on stdout
STDOUT_DISPLAY = 1;

# Set this to 1 if you wish escape the output before emailing it.
# This isn't really necessary though since the email is plain text.
ESCAPE_OUTPUT = 0

def gettext(mailtext, plainbody):
    '''
    Extract plain body text from email body.
    '''
    decode = 0
    msg = email.message_from_string(mailtext)
    
    if (msg.is_multipart()):
        for part in msg.get_payload():
            gettext(part.as_string(), plainbody)
    else:
        msgstr = msg.as_string()
        if isinstance(msgstr, str): msgstr = msgstr.split('\n')
        emptyline = msgstr.index('')
        headers = msgstr[:emptyline]

        try:
            decode = headers.index('Content-Transfer-Encoding: base64')
        except ValueError:
            pass

        body = msgstr[emptyline + 1:]
        t = msg.get_content_type()
        if t == "text/plain":
            if decode:
                msgstr = msg.get_payload(decode=True)
                try:
                    plainbody['text'] = plainbody['text'] + msgstr
                except KeyError:
                    plainbody['text'] = msgstr
                    pass
                
            else:
                try:
                    plainbody['text'] = '\n'.join(body)
                except KeyError:
                    plainbody['text'] = '\n'.join(body)
                    pass

def processtext(mFrom, mSubject, mText):
    '''
    Check ACL and whitelists. If passed, extract command and execute.
    Return command output.
    '''
    cmdoutput = {}
    cmd = ''
    output = ''
    error = ''
    
    FROM_ADDRESS_MATCH = r"^(.*)$"
    if len(sender_whitelist):
        FROM_ADDRESS_MATCH = '^.*?([\[\<])*(' + '|'.join(sender_whitelist) + ')([\]\>])*$'

    f = re.compile(FROM_ADDRESS_MATCH)        
    if not f.match(mFrom):
        print RED + "Unauthorized Sender!" + ENDC
        return cmdoutput
    
    if SUBJECT_CHECK_ENABLED:
        s = re.compile(SUBJECT_MATCH)
        if not s.match(mSubject):
            print RED + "Subject Mismatch!" + ENDC
            return cmdoutput
        
    p = re.compile(r'^CMD: (.*)$')    
    for text in mText.splitlines():
        if p.match(text):
            if len(p.match(text).group(1)):
                cmd = p.match(text).group(1)
                cmd = cmd.encode('string-escape')
            execute = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = execute.communicate()
            if error: cmdoutput[cmd] = "<ERROR>\n" + error
            else: cmdoutput[cmd] = output
    return cmdoutput


def SMail(fromname, fromaddr, toaddr, sendsubject, sendmsg):
    '''
    Authenticate to SMTP if enabled and reply to sender with plain body.
    '''
    HeaderText = 'From: ' + '"' + fromname + '" <' + fromaddr + '>\r\n'
    HeaderText += 'To: ' + toaddr + '\r\n'
    HeaderText += 'Subject: ' + sendsubject + '\r\n'
    HeaderText += '\r\n'
    try:
        if SMTPAUTH:
            try:
                S.login(SMTPUSER, SMTPPASS)
            except:
                print RED + "Error Logging to SMTP Server!" + ENDC
                sys.exit(1)
            
        S.sendmail(fromaddr, [toaddr], HeaderText + sendmsg)
    except:
        pass

    return 1

if(__name__ == "__main__"):
    while(1):
        getcmdoutput = {}
        cmd = ''
        cmdoutput = ''

        S = smtplib.SMTP(SMTPSERVER)
        M = poplib.POP3(POPSERVER)
        M.user(POPUSER)
        M.pass_(POPPASS)

        fd = open(LOGFILE, 'a')
    
        if M.stat()[1] > 0:
            print WHITE + MAGENTAB + 'You\'ve got ' + CYAN + str(len(M.list()[1])) + ENDC + WHITE + MAGENTAB + ' mails!' + ENDC
        else:
            print RED + "No new mails." + ENDC
    
        print ""
    
        mailsTotal = len(M.list()[1])
    
        for i in range(mailsTotal):
            print YELLOW + BLUEB + '-- Mail No. ' + str(i + 1) + '/' + str(mailsTotal) + ' --' + ENDC
            MyMessage = M.retr(i + 1)
    
            FullText = ""
            plainbody = {}
        
            for MessageLine in MyMessage[1]:
                    FullText += MessageLine + "\n"
            
            eMsg = email.message_from_string(FullText)
        
            print CYAN + "From: ", eMsg["from"] + ENDC
            print CYAN + "Subject: ", eMsg["subject"] + ENDC
            print CYAN + "Date: ", eMsg["date"] + ENDC
            print ""
            gettext(FullText, plainbody)
            print GREEN + plainbody.get('text', None) + ENDC
            print BLUE + '-- EndOfMail ' + str(i + 1) + ' --' + ENDC + '\n'

            print "" + BLUE + "Sending Reply ..." + ENDC,
    
            mFrom = eMsg["from"]
            mFrom = mFrom.encode('string-escape')
            mSubject = eMsg["subject"]
            mSubject = mSubject.encode('string-escape')
            getcmdoutput = processtext(mFrom, mSubject, plainbody.get('text', None))
            sendreply = ''
            for cmd, cmdoutput in getcmdoutput.items():
                sendreply += "CMD: '%s'\n== OUTPUT ==\n%s=== END ===\n\n" % (cmd, cmdoutput)

            if len(sendreply):
                if ESCAPE_OUTPUT: 
                    sendreply = cgi.escape(sendreply)
                fd.write("<pre>------------\nFrom: %s\nDate: %s\nCmd: %s\n= Output =\n%s\n------------\n\n</pre>" % (eMsg["from"], eMsg["date"], cmd, cmdoutput))
            
                if (SMail(SENDERNAME, SENDERADDRESS, eMsg["from"], SENDSUBJECT, sendreply)):
                    print GREEN + "Done." + ENDC
                else:
                    print RED + "Error!" + ENDC
                
                print ""
        
            M.dele(i + 1)
            fd.close()
    
        M.quit()


        time.sleep(EMAIL_CHECK_DELAY)
