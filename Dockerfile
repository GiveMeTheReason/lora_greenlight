FROM ubuntu:20.04

ENV TZ=UTC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
RUN apt-get update && apt-get install -y python3 python3-pip

WORKDIR /app
# for telegram-files
RUN mkdir -p ./documents
COPY requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt

# for cv2
#RUN apt-get install -y libsm6 libxext6
RUN apt-get install -y ffmpeg libsm6 libxext6


# Install zbar

RUN apt-get install -y git libzbar-dev zbar-tools \
    && pip3 install --no-cache-dir zbar-py \
    && apt purge -y git libzbar-dev python3-pip \
    && apt autoremove -y && apt-get clean && apt-get autoclean 

COPY bot.py ./

ENV BOT_TOKEN=
ENV SERVER_PATH=
ENV ALLOWED_SIZE=
ENV DAYS_TO_RELOGIN=
ENV MONGO_DATABASE=
ENV MONGO_USERNAME=
ENV MONGO_PASSWORD=
ENV MONGO_HOST=
ENV MONGO_PORT=
ENV LOGLEVEL=
ENV PORT=
ENV DOCUMENTS_PATH=

CMD ["python3", "-u", "./bot.py"]
