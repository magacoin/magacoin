### Seeds ###

Utility to generate the seeds.txt list that is compiled into the client
(see [src/wallparamsseeds.h](/src/wallparamsseeds.h) and other utilities in [contrib/seeds](/contrib/seeds)).

The seeds compiled into the release are created from pooler's DNS seed data, like this:

    curl -s https://www.magacoinpool.org/seeds.txt > seeds_main.txt
    python makeseeds.py < seeds_main.txt > nodes_main.txt
    python generate-seeds.py . > ../../src/wallparamsseeds.h

