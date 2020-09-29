<p align="center">
    <img width=500 src="static/logo-full.png?raw=true">
</p>

<h2 align="center"> Security Assessment Report geNerated Automatically </h2>

## What is SARNA?

Well, the name is clear, SARNA is a tool to generate security assessment reports automatically in DOCX format.
It aims to solve a problem I have been having. As a pentester everybody knows that writing reports sucks, and
at the end you spend a lot of time copy pasting things from other reports (like definitions or other things),
and if, for some reason, you have to do your reports in DOCX, there is no easy way to automatize that.

SARNA is a **collaborative platform** that let a group of pentesters to work together to make a great report.
You have to concentrate in hacking and breaking things, and hopefully, **SARNA will do de boring part of the report**.

### Why the name

Sarna is the Spanish name for Scabies. In Spain we have a saying "sarna con gusto no pica" in english is something 
like "Scabies with pleasure does not itch". It is a little bit disgusting, but at the end, it means that if you have
something bad (like having to make a report), but you get something good with it in exchange (like doing it 
fast with this tool), it is not that bad at the end. 

### Run test environment

To run a simple test environment in order to check what is SARNA yo can use the docker-compose recipe

**PLEASE DO NOT USE DOCKER-COMPOSE RECIPE FOR PRODUCTION WITHOUT CHANGING PASSWORDS AND SECRETS**

```bash
docker-compose up
```
This will take a while for the first time. At the end of the process your SARNA Server should 
be running at <http://localhost:5000>

You only need to create a new user

```bash
docker-compose exec sarna /bin/sh
flask user add -r manager <user_name>
```

Please referer to `flask user add --help` for more info.

### Common issues in development

- If you get an error while starting the image in your local environment about file permissions, check that the `entrypoint.sh` script has UNIX line endings (LF) instead of Windows' (CRLF)

#### DB Migrations

Check that you have the latest migration. First:

```bash
docker-compose exec sarna /bin/sh
flask db history
```
You should now see a list of every available migration. Check that you're at the HEAD revision:

```bash
flask db current
```

Or execute the ones missing:

```bash
flask db upgrade <revision>
```

### Create a migration

Write your model changes into the Python classes at `sarna\model` and then, with the PostgresQL container running, execute in your host CMD (at the project's root):

```bash
flask db migrate -m "Your migration description message"
```

To quickly update the database image after creating a migration, stop the SARNA containers and run the following:

```bash
docker container rm sarna_psql_1 \
    && docker volume rm sarna_vol_sarna_db \
    && docker-compose up --build
```