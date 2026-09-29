# Pure jq functions shared by measure-storage.sh and summarize.sh.
# Every duration is integer or decimal milliseconds; every size is MiB.
# Nothing here reads the cluster, so fixtures cover all of it.

# Days since 1970-01-01 for a proleptic Gregorian date (days_from_civil).
def days_from_civil($y; $m; $d):
  (if $m <= 2 then $y - 1 else $y end) as $yy
  | ($yy / 400 | floor) as $era
  | ($yy - $era * 400) as $yoe
  | (((153 * (if $m > 2 then $m - 3 else $m + 9 end) + 2) / 5 | floor) + $d - 1) as $doy
  | ($yoe * 365 + ($yoe / 4 | floor) - ($yoe / 100 | floor) + $doy) as $doe
  | $era * 146097 + $doe - 719468;

# RFC 3339 UTC timestamp, with optional fractional seconds, to epoch ms.
# Anything else (null, empty, non-UTC) becomes null rather than a guess.
# Computed directly: jq 1.6 fromdateiso8601 applies the host's DST.
def ts_ms:
  if type != "string" then null
  else
    [capture("^(?<y>[0-9]{4})-(?<mo>[0-9]{2})-(?<d>[0-9]{2})T(?<h>[0-9]{2}):(?<mi>[0-9]{2}):(?<s>[0-9]{2})(\\.(?<frac>[0-9]+))?(Z|\\+00:00)$")]
    | if length == 0 then null
      else .[0]
        | (days_from_civil(.y | tonumber; .mo | tonumber; .d | tonumber) * 86400
            + (.h | tonumber) * 3600 + (.mi | tonumber) * 60 + (.s | tonumber)) * 1000
          + (((.frac // "") + "000")[0:3] | tonumber)
      end
  end;

def delta($from; $to):
  if ($from | type) == "number" and ($to | type) == "number" then $to - $from else null end;

def round3: if type == "number" then (. * 1000 | round) / 1000 else . end;
def round1: if type == "number" then (. * 10 | round) / 10 else . end;

# Nearest-rank percentiles over the numbers in an array; non-numbers are
# ignored. pN is the value at rank ceil(N * n / 100).
def stats:
  [.[] | select(type == "number")] | sort as $v | ($v | length) as $n
  | if $n == 0 then {n: 0, min: null, p50: null, p95: null, max: null, mean: null}
    else {
      n: $n,
      min: $v[0],
      p50: $v[(((50 * $n) + 99) / 100 | floor) - 1],
      p95: $v[(((95 * $n) + 99) / 100 | floor) - 1],
      max: $v[$n - 1],
      mean: (($v | add) / $n | round3)
    }
    end;

# Kubernetes resource quantities from the metrics API.
def cpu_mcores:
  if type == "number" then . * 1000
  elif type != "string" then null
  else
    [capture("^(?<n>[0-9]+(\\.[0-9]+)?)(?<u>[num]?)$")]
    | if length == 0 then null
      else .[0] | (.n | tonumber) as $v
        | if .u == "n" then $v / 1000000
          elif .u == "u" then $v / 1000
          elif .u == "m" then $v
          else $v * 1000 end
        | round3
      end
  end;

def mem_mib:
  if type == "number" then . / 1048576 | round3
  elif type != "string" then null
  else
    [capture("^(?<n>[0-9]+(\\.[0-9]+)?)(?<u>Ki|Mi|Gi|Ti|k|M|G|T)?$")]
    | if length == 0 then null
      else .[0] | (.n | tonumber) as $v
        | {"Ki": 1024, "Mi": 1048576, "Gi": 1073741824, "Ti": 1099511627776,
           "k": 1000, "M": 1000000, "G": 1000000000, "T": 1000000000000}[.u // ""] as $scale
        | ($v * ($scale // 1)) / 1048576 | round3
      end
  end;

# Earliest time of an Event with this reason. The scheduler writes eventTime
# (microseconds); kubelet and controllers write firstTimestamp (seconds).
def first_event_ms($events; $reason):
  [($events.items // [])[] | select(.reason == $reason)
    | (.eventTime // .firstTimestamp // .metadata.creationTimestamp) | ts_ms
    | select(. != null)]
  | min;

def condition_ms($object; $type):
  [($object.status.conditions // [])[] | select(.type == $type and .status == "True")
    | .lastTransitionTime | ts_ms | select(. != null)]
  | first // null;

# Server-side timeline of one volume start, from the object bundle
# {pvc, pv, pod, pvc_events, pod_events}. Object timestamps have one-second
# precision; the Scheduled event has microsecond precision.
def server_timeline:
  . as $in
  | {
      pvc_created_ms: ($in.pvc.metadata.creationTimestamp | ts_ms),
      pod_created_ms: ($in.pod.metadata.creationTimestamp | ts_ms),
      scheduled_ms: (first_event_ms($in.pod_events; "Scheduled") // condition_ms($in.pod; "PodScheduled")),
      pv_created_ms: ($in.pv.metadata.creationTimestamp | ts_ms),
      provisioning_succeeded_ms: first_event_ms($in.pvc_events; "ProvisioningSucceeded"),
      attach_succeeded_ms: first_event_ms($in.pod_events; "SuccessfulAttachVolume"),
      container_started_ms: ([($in.pod.status.containerStatuses // [])[]
        | .state.running.startedAt | ts_ms | select(. != null)] | max),
      containers_ready_ms: condition_ms($in.pod; "ContainersReady")
    }
  | . + {
      scheduled_after_create_ms: delta(.pvc_created_ms; .scheduled_ms),
      provision_ms: delta(.scheduled_ms; .pv_created_ms),
      attach_ms: delta(.pv_created_ms; .attach_succeeded_ms),
      create_to_ready_ms: delta(.pvc_created_ms; .containers_ready_ms)
    }
  | . + {
      image_pulled: any(($in.pod_events.items // [])[];
        .reason == "Pulled" and ((.message // "") | test("Successfully pulled"))),
      pv_name: ($in.pvc.spec.volumeName // null),
      node: ($in.pod.spec.nodeName // null),
      csi_driver: ($in.pv.spec.csi.driver // null),
      volume_mode: ($in.pv.spec.volumeMode // null)
    };

# One fio job's result from fio --output-format=json. $spec is the harness'
# own job description {name, rw, bs, iodepth, direction}.
def fio_summary($spec):
  (.jobs // [])[0] as $job
  | ($job[$spec.direction] // {}) as $d
  | (($d.clat_ns // $d.lat_ns // {}).percentile // {}) as $p
  | $spec + {
      iops: ($d.iops | round1),
      bw_mib_s: (if ($d.bw_bytes | type) == "number" then $d.bw_bytes / 1048576 | round1 else null end),
      lat_us: {
        mean: (if (($d.clat_ns // {}).mean | type) == "number" then $d.clat_ns.mean / 1000 | round1 else null end),
        p50: (if ($p["50.000000"] | type) == "number" then $p["50.000000"] / 1000 | round1 else null end),
        p95: (if ($p["95.000000"] | type) == "number" then $p["95.000000"] / 1000 | round1 else null end),
        p99: (if ($p["99.000000"] | type) == "number" then $p["99.000000"] / 1000 | round1 else null end),
        p99_9: (if ($p["99.900000"] | type) == "number" then $p["99.900000"] / 1000 | round1 else null end)
      },
      runtime_ms: ($job[$spec.direction].runtime // null),
      error: ($job.error // null)
    };

def metrics_window:
  {
    samples: length,
    node_cpu_mcores: (map(.node_cpu_mcores) | stats | {mean, max}),
    node_mem_mib: (map(.node_mem_mib) | stats | {mean, max}),
    storage_cpu_mcores: (map(.storage_cpu_mcores) | stats | {mean, max}),
    storage_mem_mib: (map(.storage_mem_mib) | stats | {mean, max})
  };

# Per-phase node and storage-system usage, plus each phase's mean increase
# over the baseline phase when one was sampled.
def metrics_summary:
  if length == 0 then {available: false}
  else
    (group_by(.phase) | map({key: .[0].phase, value: metrics_window}) | from_entries) as $phases
    | ($phases.baseline // null) as $base
    | {
        available: true,
        phases: $phases,
        over_baseline: (
          if $base == null then null
          else $phases | with_entries(select(.key != "baseline") | .value = {
            node_cpu_mcores: delta($base.node_cpu_mcores.mean; .value.node_cpu_mcores.mean) | round3,
            node_mem_mib: delta($base.node_mem_mib.mean; .value.node_mem_mib.mean) | round3,
            storage_cpu_mcores: delta($base.storage_cpu_mcores.mean; .value.storage_cpu_mcores.mean) | round3,
            storage_mem_mib: delta($base.storage_mem_mib.mean; .value.storage_mem_mib.mean) | round3
          })
          end)
      }
  end;

def volume_start_stats:
  {
    client: {
      create_to_bound_ms: (map(.client.create_to_bound_ms) | stats),
      create_to_ready_ms: (map(.client.create_to_ready_ms) | stats),
      bound_to_ready_ms: (map(.client.bound_to_ready_ms) | stats)
    },
    server: {
      scheduled_after_create_ms: (map(.server.scheduled_after_create_ms) | stats),
      provision_ms: (map(.server.provision_ms) | stats),
      attach_ms: (map(.server.attach_ms) | stats),
      create_to_ready_ms: (map(.server.create_to_ready_ms) | stats)
    }
  };

def teardown_stats:
  map(select(.teardown.status == "ok") | .teardown)
  | {
      n: length,
      pod_delete_ms: (map(.pod_delete_ms) | stats),
      pvc_delete_ms: (map(.pvc_delete_ms) | stats),
      pv_delete_ms: (map(.pv_delete_ms) | stats),
      total_ms: (map(.total_ms) | stats)
    };

# The recorded Longhorn v1 cold path on Dev (docs/plans/2026-09-29-fast-sandbox-starts.md).
def longhorn_v1_reference:
  {
    source: "docs/plans/2026-09-29-fast-sandbox-starts.md (Dev, 2026-09-29, one traced start)",
    provision_ms: 3000,
    attach_ms: 10000
  };

# The whole evidence bundle to one summary document.
def summarize:
  . as $b
  | (($b.attach // []) | map(select(.warmup != true))) as $measured
  | ($measured | map(select(.status == "ok"))) as $ok
  | ($b.phases // []) as $phases
  | {
      schema: "codewire.sh/storage-measure-summary/v1",
      run_id: $b.meta.run_id,
      started_at: $b.meta.started_at,
      inputs: $b.meta.inputs,
      cluster: $b.meta.cluster,
      status: (if any($phases[]; .status == "failed") then "failed" else "ok" end),
      phases: $phases,
      provision_attach: ({
        runs_requested: $b.meta.inputs.runs,
        warmup_runs: (($b.attach // []) | map(select(.warmup == true)) | length),
        runs_measured: ($measured | length),
        runs_ok: ($ok | length),
        runs_with_image_pull: ($ok | map(select(.server.image_pulled == true)) | length),
        nodes: ($ok | map(.server.node) | unique)
      } + ($ok | volume_start_stats)),
      teardown: ($measured | teardown_stats),
      fio: (if $b.fio == null then null else ($b.fio | map({key: .name, value: del(.name)}) | from_entries) end),
      workload: (
        if $b.workload == null then null
        else {
          info: ($b.workload.info // null),
          steps: (($b.workload.steps // []) | map({key: .step, value: del(.step)}) | from_entries)
        }
        end),
      bench: ($b.bench // null),
      snapshot: ($b.snapshot // null),
      remote_snapshot: ($b.remote // null),
      node_overhead: (($b.metrics // []) | metrics_summary),
      cleanup: ($b.cleanup // null),
      reference: {longhorn_v1: longhorn_v1_reference}
    };

# One metrics sample: node usage, plus the summed usage of the storage
# system's pods on that node when a storage namespace was given.
def metrics_sample($t; $phase; $node; $nm; $pods; $pm):
  [($pods.items // [])[] | select(.spec.nodeName == $node) | .metadata.name] as $on_node
  | [($pm.items // [])[] | select(.metadata.name as $n | any($on_node[]; . == $n))] as $used
  | {
      t_ms: $t,
      phase: $phase,
      node: $node,
      node_cpu_mcores: ($nm.usage.cpu | cpu_mcores),
      node_mem_mib: ($nm.usage.memory | mem_mib),
      storage_pods: (if $pods == null then null else $used | length end),
      storage_cpu_mcores: (if $pods == null then null
        else [$used[].containers[]? | .usage.cpu | cpu_mcores] | add // 0 | round3 end),
      storage_mem_mib: (if $pods == null then null
        else [$used[].containers[]? | .usage.memory | mem_mib] | add // 0 | round3 end)
    };

# Manifests. $cfg is the harness configuration object (build_config).
def sm_labels($cfg; $role):
  {
    "app.kubernetes.io/managed-by": "codewire-storage-measure",
    "codewire.sh/storage-measure": $cfg.run_id,
    "codewire.sh/storage-measure-role": $role
  };

def sm_metadata($cfg; $name; $role):
  {name: $name, namespace: $cfg.namespace, labels: sm_labels($cfg; $role)};

def sm_list: {apiVersion: "v1", kind: "List", items: .};

def sm_pvc($cfg; $name; $role; $snapshot):
  {
    apiVersion: "v1",
    kind: "PersistentVolumeClaim",
    metadata: sm_metadata($cfg; $name; $role),
    spec: ({
      accessModes: ["ReadWriteOnce"],
      storageClassName: $cfg.storage_class,
      resources: {requests: {storage: $cfg.pvc_size}}
    } + (if ($snapshot // "") == "" then {}
         else {dataSource: {apiGroup: "snapshot.storage.k8s.io", kind: "VolumeSnapshot", name: $snapshot}} end))
  };

# Idles until deleted; TERM ends it at once so deletion time measures storage,
# not a grace period.
def sm_idle_command($deadline): ["sh", "-c", "trap 'exit 0' TERM; sleep \($deadline) & wait $!"];

def sm_restricted: {allowPrivilegeEscalation: false, runAsNonRoot: true, capabilities: {drop: ["ALL"]}};

# The workspace pod's identity and fsGroup handling (sandbox/template/workspace.rs).
def sm_pod_spec($cfg; $deadline):
  {
    restartPolicy: "Never",
    automountServiceAccountToken: false,
    enableServiceLinks: false,
    activeDeadlineSeconds: $deadline,
    terminationGracePeriodSeconds: 10,
    securityContext: {
      runAsUser: 1000, runAsGroup: 1000, fsGroup: 1000,
      fsGroupChangePolicy: "OnRootMismatch",
      seccompProfile: {type: "RuntimeDefault"}
    }
  }
  + (if $cfg.runtime_class == "" then {} else {runtimeClassName: $cfg.runtime_class} end)
  + (if $cfg.node == "" then {} else {nodeSelector: {"kubernetes.io/hostname": $cfg.node}} end)
  + (if $cfg.image_pull_secret == "" then {} else {imagePullSecrets: [{name: $cfg.image_pull_secret}]} end);

def sm_probe_pod($cfg; $name; $pvc; $role):
  {
    apiVersion: "v1",
    kind: "Pod",
    metadata: sm_metadata($cfg; $name; $role),
    spec: (sm_pod_spec($cfg; $cfg.probe_deadline_s) + {
      containers: [{
        name: "probe",
        image: $cfg.probe_image,
        imagePullPolicy: "IfNotPresent",
        command: sm_idle_command($cfg.probe_deadline_s),
        securityContext: (sm_restricted + {readOnlyRootFilesystem: true}),
        resources: {requests: {cpu: "100m", memory: "64Mi"}, limits: {cpu: "500m", memory: "128Mi"}},
        volumeMounts: [{name: "workspace", mountPath: "/workspace"}]
      }],
      volumes: [{name: "workspace", persistentVolumeClaim: {claimName: $pvc}}]
    })
  };

def sm_bench_pod($cfg; $name; $pvc; $fio_pvc; $scripts):
  ($cfg.dind_image != "") as $docker
  | {
      apiVersion: "v1",
      kind: "Pod",
      metadata: sm_metadata($cfg; $name; "bench"),
      spec: (sm_pod_spec($cfg; $cfg.bench_deadline_s) + {
        containers: (
          [{
            name: "workload",
            image: $cfg.workload_image,
            imagePullPolicy: "IfNotPresent",
            command: sm_idle_command($cfg.bench_deadline_s),
            securityContext: sm_restricted,
            env: ([{name: "SM_ROOT", value: "/workspace/sm"}]
              + (if $docker then [{name: "DOCKER_HOST", value: "unix:///var/run/docker/docker.sock"}] else [] end)),
            resources: {
              requests: {cpu: $cfg.workload_cpu, memory: $cfg.workload_memory},
              limits: {cpu: $cfg.workload_cpu, memory: $cfg.workload_memory}
            },
            volumeMounts: ([{name: "workspace", mountPath: "/workspace"}, {name: "scripts", mountPath: "/sm", readOnly: true}]
              + (if $docker then [{name: "docker-sock", mountPath: "/var/run/docker"}] else [] end))
          }]
          + (if $fio_pvc == "" then [] else [{
            name: "fio",
            image: $cfg.fio_image,
            imagePullPolicy: "IfNotPresent",
            command: sm_idle_command($cfg.bench_deadline_s),
            securityContext: sm_restricted,
            resources: {requests: {cpu: "1", memory: "1Gi"}, limits: {cpu: "2", memory: "2Gi"}},
            volumeMounts: [{name: "fio", mountPath: "/fio"}]
          }] end)
          + (if $docker then [{
            name: "dind",
            image: $cfg.dind_image,
            imagePullPolicy: "IfNotPresent",
            command: ["sh", "/sm/dind-bootstrap.sh"],
            securityContext: {privileged: true, runAsUser: 0, runAsGroup: 0, runAsNonRoot: false},
            env: [
              {name: "DOCKER_TLS_CERTDIR", value: ""},
              {name: "SM_DOCKER_DATA_IMAGE", value: "/workspace/.codewire/docker-data.ext4"},
              {name: "SM_DOCKER_DATA_SIZE", value: $cfg.docker_data_size}
            ],
            resources: {requests: {cpu: "500m", memory: "1Gi"}, limits: {cpu: "2", memory: "4Gi"}},
            volumeMounts: [
              {name: "workspace", mountPath: "/workspace"},
              {name: "docker-sock", mountPath: "/var/run/docker"},
              {name: "scripts", mountPath: "/sm", readOnly: true}
            ]
          }] else [] end)),
        volumes: (
          [{name: "workspace", persistentVolumeClaim: {claimName: $pvc}},
           {name: "scripts", configMap: {name: $scripts, defaultMode: 365}}]
          + (if $fio_pvc == "" then [] else [{name: "fio", persistentVolumeClaim: {claimName: $fio_pvc}}] end)
          + (if $docker then [{name: "docker-sock", emptyDir: {medium: "Memory"}}] else [] end))
      })
    };

def sm_scripts_configmap($cfg; $name; $workload; $dind):
  {
    apiVersion: "v1",
    kind: "ConfigMap",
    metadata: sm_metadata($cfg; $name; "scripts"),
    data: {"workload.sh": $workload, "dind-bootstrap.sh": $dind}
  };

def sm_volume_snapshot($cfg; $name; $class; $pvc; $role):
  {
    apiVersion: "snapshot.storage.k8s.io/v1",
    kind: "VolumeSnapshot",
    metadata: sm_metadata($cfg; $name; $role),
    spec: {volumeSnapshotClassName: $class, source: {persistentVolumeClaimName: $pvc}}
  };
