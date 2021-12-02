# Traffic Monitoring Analysis - QoE Classification based on network traffic

## Installation

In order to develop/test the application you simply need to download:

- Docker
- docker-compose

Follow the instructions for your operation system. Theoretically, it is a straitforward operation.

## Deploying

If you visit the label-manager/config directory you will notice a .env.example file. Create a copy of this file and name it ".env". This file contains the **Client ID**, **Client Token** for twitch developer api. This will allow us to query the Twitch server in order to get the current streaming channels. Alexis has created a twitch account called "tma-project" and will provide you the credentials in order to fill in these two parameters in the .env file. 

Finally, there is the **Database Url** parameter. This contains the information on how django application connects to the database. You need to replace it with the following link:

DATABASE_URL=psql://postgres:postgres@localhost:5432/postgres

Now, go to the docker/ directory. To "compile" the code you need to run 

``` 
docker-compose build
```

At the first time, it will try to download all the necessary images (think of it like templates of Virtual Machines; but for docker). **Every time you make a change to the code you need to stop the application and execute docker-compose build in order to compile the new changes!**

Now you're ready to run the application:

``` 
docker-compose up
```

This will launch two services:

- Django application
- Postgresql Database

**(Update)** For the bandwidth limitation to be performed you need to launch a script as root. Basically, the script (executed on host) receives commands from the container and enforces the bandwidth rules to the host's interfaces.

In the config/.env file you need to add another field that contains the interface of your pc that is connected to the internet (perform 'ip a' to find out more).

INTERFACE=<name of interface>

Open a new tab and go to scripts/bw_limit directory. Execute the script:

```
sudo bash bw_handler.sh
```

Make sure that you have already installed wondershaper inside the project. Since we are simply referencing another github project we have the respective folder, but we don't have the content. To get the content you simply need to run the following command in the root project directory:

```
git clone https://github.com/magnific0/wondershaper.git
```

## Debugging 

To view the state of both services execute:

```
docker container ls
```

For debugging purposes you may need to connect to one of the two services (like doing ssh to a VM). To do that first you need to find out the container id of each container (use the command docker container ls). Then execute the following command:

```
docker exec -it <container id> sh
```

This opens a shell to the service's container where you get to see all the files that it has. For example, if you want to perform some queries to the database to make sure that everything is stored properly, once you have connected to the respective container, execute the command

```
psql -h localhost -U postgres
```

## Db Model

For the scope of the dataset creation two models have been created (in models.py):

**1. Training**

| Training table ||
| ---- | ----------- |
| name | TextField |
| created_at | DateTimeField |
| finished_at | DateTimeField |
| number_of_videos | IntegerField |
| bw_limitations (* Comma seperated string with all the limitations in Mbps e.g. "0.25, 1, 2)| TextField |
| session_duration (* How many seconds will the tests last) | FloatField |
| has_finished (* Whether the training has finished) | BooleanField |

```
SELECT * FROM web_training;
```

**2. Session**

| Session table ||
| ---- | ----------- |
| name | TextField |
| training | ForeignKey |
| created_at | DateTimeField |
| finished_at | DateTimeField |
| url (* The name of the channel that we will stream for the test) | TextField |
| status (* -1 for "not captured", 0 for "under capturing", 1 for "captured")| IntegerField |
| bw_limitation (* Specific bandwidth limitation in Mbps for this session)| FloatField |
| application_data (* Application data in json)| TextField |
| network_data (* Network data in json) | TextField |

```
SELECT * FROM web_session;
```

## In Brief

Once the application launches and you connect to "localhost:8000" you will see a simple form where you can insert the number of videos (e.g. 100), the duration of each session playback in seconds (e.g. 60) and the bandwidth limitation in Mbps as a comma separated string (e.g. "0.25, 1, 2").

Once you click on Submit button then the following takes place on the backend (this is also explained in the workflow diagram):

- Create a new entry for Training db table.
- Get 100 streaming channel names.
- Create N entries for Session db table where N is the number of videos that shall be included in the test. In each session entry, a bandwidth limiation value will be given so that all bandwidth limitations have equal representation (e.g. For 100 videos and 2 bandwidth limitations we have 50 sessions for each bandwidth)
- Client requests a videoUrl
- Client notifies the server that it starts playing a video (and client starts playing the video :). Client waits for 20 seconds and then starts capturing application data ).
- Server starts capturing packets for the defined duration of the session.
- Client - after the defined duration of the session has passed - sends a finishVideo request to the Server by providing the application data that it calculated (so far we simply return the number of counts)
- Server calculates TCP statistics using tstat.
- Server takes the network statistics, application data and stores them to the db
- Client requests another videoUrl
...

Once all the sessions have been captured we can export the collected dataset.
  



