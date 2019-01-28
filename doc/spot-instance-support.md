### Known Issues

- When using `cancel-spot-instance-request` to cancel fulfilled spot instance
  requests *without* terminating the instance, `list-spot-instance-requests`
  and `list-spot-instance-nodes` will no longer display the instance. This is
  because the spot instance has been effectively cancelled and is no longer
  registered with Tortuga.

  The instance will remain in Tortuga, as expected, until terminated (deleted).
