const fs = require('fs')
const path = require('path')
const cfg = JSON.parse(fs.readFileSync(path.join(__dirname, 'config.json'), 'utf8'))
fetch('https://slack.com/api/chat.postMessage', {
  method: 'POST',
  headers: { Authorization: `Bearer ${process.env.SLACK_TOKEN}` },
  body: JSON.stringify({ channel: cfg.channel, text: 'summary' }),
})
