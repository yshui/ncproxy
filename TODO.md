* Potential race condition between {local,remote} end with websocket close
* Connection close on server result in local_end being sent after websocket close
* Use ping/pong for remote/local_end. Avoid race.
