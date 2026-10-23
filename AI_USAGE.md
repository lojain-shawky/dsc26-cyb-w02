# AI usage: dsc26-cyb-w02

Keep the three headings below exactly as they are. The grader stops and scores 0 if this file is
missing or any of the three headings is missing. It does not score what you write; your Track
Mentor reads it, and the W8 defence can ask about it.

## Tools

<!-- Which AI tools you used (or "none"), and for which parts of the task. -->
Gemini -> Used for writing Python core logic in `tmcheck/core.py`, creating the CLI entry point in `tmcheck/__main__.py`, troubleshooting local virtual environment set up and Git commands, and brainstorming system specific threat scenarios for `models/rawaj_scoring.yaml`

## What AI got wrong

<!-- At least one thing an AI tool got wrong that you changed, and how you noticed:
     a test, the docs, running it. -->
It suggested an impact for threat T29 to be 2, but I saw it should be 3 as if the identity of the analyst repudated and there's a case we investigate in, it would cause a problem for us -> I noticed it when I was writing the YAML File

## In my own words

<!-- One or two sentences each, written without AI. -->

1. Why does a data store have no Spoofing threats in STRIDE per element, and where does that threat go instead?
The data store is static doesn't do actions or need an identity to do something, it's just a place to keep data safe in it. Spofing targets something takes actions like the external entity, I need to be the analyst to be able to view the console

2. Which of your eleven new threats would you fix first, and why that one?
I would fix T38 as it has the high risk rank: 3*5=15 and it exposes sensitive data of customers which will lead to bad sequences 
