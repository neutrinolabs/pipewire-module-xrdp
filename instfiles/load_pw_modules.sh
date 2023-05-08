#!/bin/sh

status=0

if [ -n "$XRDP_SESSION" -a -n "$XRDP_SOCKET_PATH" ]; then
    # These values are not present on xrdp versions before v0.9.8

    OBJECT_IDS=$(pw-cli ls Node | sed -e "s/^[^a-z]//" | grep -w "^id" | sed -e "s/^[^0-9]*//" -e "s/[^0-9]/-/" | cut -d- -f1)
    for OBJECT_ID in $OBJECT_IDS; do
        NODE_NAME=$(pw-cli info $OBJECT_ID | grep -w "node\.name" | cut -d\" -f2)
        if [ "$NODE_NAME" = "xrdp-sink" -o "$NODE_NAME" = "xrdp-source" ]; then
            pw-cli destroy $OBJECT_ID
        fi
    done

    # Kill module, if it is working
    #PID=$(ps -u $(id -u) -o pid,ruser,cmd | grep libpipewire-module-xrdp-pipewire | grep -v grep | sed -e 's/^ *//' | cut -d' ' -f1)
    #if [ -n "$PID" ]; then
    #    kill -HUP $PID
    #fi

    if [ "$1" = "-d" ]; then exit; fi

    export PIPEWIRE_LOG_SYSTEMD=false
    if [ "$1" = "-l" ]; then
        # debug:  0:none, 1:error, 2:warnings, 3:info, 4:debug, 5:trace
        if [ -n "$2" ]; then
            export PIPEWIRE_DEBUG=$2
        else
            export PIPEWIRE_DEBUG=3
        fi
        export PIPEWIRE_LOG=/tmp/xrdp_pipewire_$(echo $DISPLAY | sed -e 's/^[^0-9]//' | cut -d. -f1).log
    else
        export PIPEWIRE_DEBUG=1
    fi

    # Reload modules
    PWCLI=pw-cli
    if [ "$(pipewire --version | sed -e "s/[ a-zA-Z]//g" | tail -n 1)" = "0.3.58" ]; then
        PWCLI=$(dirname $0)/pw-cli_0358_mod
    fi

    QUANTUMVAL=2048
    QUANTUMVAL2=$(($QUANTUMVAL * 2))

    # enable both xrdp-sink ans xrdp-source
    $PWCLI -m -d load-module libpipewire-module-xrdp-pipewire sink.node.latency=$QUANTUMVAL sink.stream.props={node.name=xrdp-sink} source.stream.props={node.name=xrdp-source} > /dev/null &
    # enable xrdp-sink only
    # $PWCLI -m -d load-module libpipewire-module-xrdp-pipewire sink.node.latency=$QUANTUMVAL sink.stream.props={node.name=xrdp-sink} > /dev/null &
    # enable xrdp-source only
    # $PWCLI -m -d load-module libpipewire-module-xrdp-pipewire source.stream.props={node.name=xrdp-source} > /dev/null &

    sleep 1

    #increase the quantum(latency) value to reduce choppy audio
    # from PipeWire debian
    # https://wiki.debian.org/PipeWire#choppy_audio_on_systems_with_high_load
    pw-metadata -n settings 0 clock.force-quantum $QUANTUMVAL >/dev/null
    pw-metadata -n settings 0 default.clock.force-quantum $QUANTUMVAL2 >/dev/null
    pw-metadata -n settings 0 default.clock.quantum $QUANTUMVAL2 >/dev/null
    pw-metadata -n settings 0 default.clock.min-quantum $QUANTUMVAL2 >/dev/null
    # set default sample rate = 44100, because xrdp uses it.
    pw-metadata -n settings 0 default.clock.rate 44100 >/dev/null

    pactl set-default-sink xrdp-sink
    pactl set-default-source xrdp-source
fi

exit $status
