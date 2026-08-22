[
  .spec.template.spec.containers[]?
  | .envFrom[]?
  | .configMapRef?
  | select(. != null and ((.optional // false) == false))
] as $required
| if
    ($required | length) == 1
    and ($required[0].name | type == "string")
    and ($required[0].name | test("^codewire-config-[2456789bcdfghkmt]{10}$"))
  then
    $required[0].name
  else
    error("expected exactly one required generated runtime ConfigMap")
  end
