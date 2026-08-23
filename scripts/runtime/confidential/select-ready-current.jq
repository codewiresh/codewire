. as $object
| $object.metadata.generation == $object.status.observedGeneration
  and any(
    $object.status.conditions[]?;
    .type == "Ready"
      and .status == "True"
      and .observedGeneration == $object.metadata.generation
  )
