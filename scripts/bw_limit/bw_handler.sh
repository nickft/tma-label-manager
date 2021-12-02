
docker_container_name="docker_label-manager"

enforce_bandwidth_limitation () {
  echo "Enforcing $1 $2 by executing wondershaper -a $1 -d $2"
}

flush_bandwidth_limitation () {
  echo "Flushing $1 by executing wondershaper -ca $1"
}

rm bw_limit

echo "Pipe doesn't exist. Creating a new one..."
mkfifo bw_limit

echo "Start bandwidth handler"

while docker container ls | grep $docker_container_name &> /dev/null;
do
    # Define commands
    # i)  enforce <interface> <kbps>
    # ii) flush <interface>
    cmd=`cat bw_limit`;

    if [[ $cmd == enforce* ]]; then

        interface=`echo -n $cmd | cut -d ' ' -f2`
        bw_in_kbps=`echo -n $cmd | cut -d ' ' -f3`

        enforce_bandwidth_limitation $interface $bw_in_kbps
    else
        interface=`echo -n $cmd | cut -d ' ' -f2`
        flush_bandwidth_limitation $interface
    fi
done


