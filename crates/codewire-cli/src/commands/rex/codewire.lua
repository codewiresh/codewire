-- Codewire for Rex: run commands, shells and agents in Codewire environments
-- from the command palette, each in a pane beside the one you are in.
--
-- `cw setup rex` loads this from Rex's config (~/.config/rex/init.lua):
--
--   dofile("/path/to/plugins/codewire/init.lua").setup({
--     cw = "/path/to/cw",
--     environment = { name = "app", location = "local VM" },
--   })
--
-- `environment` is the one `cw use` selected, or nil. cw rewrites that line
-- and reloads Rex's config whenever the selection changes, so the actions
-- name it, and the ones that cannot apply to it are left out.
--
-- The actions run that cw on the machine of the Rex server, so they refuse a
-- session on another host, where that cw is not.

local M = {}

local SHELL = "com.superlogical.terminal.shell"
local TERMINAL = "com.superlogical.terminal"
-- The status record `cw attach` reports in its pane. Its title is
-- ENV/SESSION, which is how an action finds the session a pane shows.
local RECORD = "codewire/session"

-- Becomes `cw run`, asking for what it needs first: an environment when
-- `choose` is 1 (`cw use`, which offers to create one when there are none),
-- then a command when none was given. claude or codex opens that agent's
-- own terminal UI, anything else runs through sh in the environment. Words
-- after claude or codex are split on blanks, never expanded here.
-- Arguments: cw, environment (or empty), command (or empty), choose, where.
local RUN = [==[
cw=$1 env=$2 line=$3 choose=$4 where=$5
if [ "$choose" = 1 ]; then
  if ! "$cw" use; then printf '\nPress enter to close.'; read -r _; exit 1; fi
  where=
  echo
fi
if [ -z "$line" ]; then
  printf 'Run in %s\n' "${where:-the selected environment}"
  printf 'Command (any command, or claude or codex): '
  IFS= read -r line || exit 0
fi
case $line in *[![:space:]]*) ;; *) exit 0 ;; esac
set -f
set -- $line
agent=
case $1 in claude|codex) agent=$1 ;; esac
rest=$*
if [ -n "$agent" ]; then rest=${rest#"$agent"}; fi
set -- "$cw" run
if [ -n "$env" ]; then set -- "$@" --in "$env"; fi
if [ -n "$agent" ]; then
  set -- "$@" "$agent"
  case $rest in *[![:space:]]*)
    set -- "$@" --
    for word in $rest; do set -- "$@" "$word"; done
  ;; esac
else
  set -- "$@" -- sh -c "$line"
fi
exec "$@"
]==]

-- `cw exec`: asks for an environment when `choose` is 1 and for a command
-- when none was given, runs it once with a terminal, and keeps the pane
-- open with how it ended. Arguments: cw, environment (or empty), command
-- (or empty), choose, where.
local ONCE = [==[
cw=$1 env=$2 line=$3 choose=$4 where=$5
if [ "$choose" = 1 ]; then
  if ! "$cw" use; then printf '\nPress enter to close.'; read -r _; exit 1; fi
  where=
  echo
fi
if [ -z "$line" ]; then
  printf 'Run once in %s\n' "${where:-the selected environment}"
  printf 'Command: '
  IFS= read -r line || exit 0
fi
case $line in *[![:space:]]*) ;; *) exit 0 ;; esac
set -- "$cw" exec
if [ -n "$env" ]; then set -- "$@" --in "$env"; fi
"$@" -t -- sh -c "$line"
status=$?
printf '\n[exited with status %s] Press enter to close.' "$status"
read -r _
]==]

-- Chooses an environment with `cw use`, then becomes the rest of the
-- arguments: a cw command for the environment just chosen.
local CHOOSE_THEN = [==[
cw=$1; shift
if ! "$cw" use; then printf '\nPress enter to close.'; read -r _; exit 1; fi
echo
exec "$cw" "$@"
]==]

-- Asks for a message and sends it with `cw msg`, then waits so its result
-- can be read. Arguments: cw, environment, session, --local, --cloud or empty.
local MSG = [==[
cw=$1 env=$2 session=$3 placement=$4
printf 'Message to %s/%s: ' "$env" "$session"
IFS= read -r line || exit 0
case $line in *[![:space:]]*) ;; *) exit 0 ;; esac
if [ -n "$placement" ]; then
  "$cw" "$placement" msg "$env" --session "$session" "$line"
else
  "$cw" msg "$env" --session "$session" "$line"
fi
printf '\nPress enter to close.'
read -r _
]==]

-- Runs a cw command and waits so its output can be read.
local SHOW = [==[
"$@"
printf '\nPress enter to close.'
read -r _
]==]

function M.setup(opts)
  opts = opts or {}
  local cw = opts.cw or "cw"
  local selected = type(opts.environment) == "table" and opts.environment or nil
  local name = selected and tostring(selected.name) or nil
  local where = selected and (name .. " · " .. tostring(selected.location)) or ""
  -- Ports and VS Code reach a sandbox, not a trusted host.
  local sandbox = selected ~= nil
    and (selected.location == "local VM" or selected.location == "cloud")

  local function local_only(ctx)
    if ctx.server ~= nil then
      error("codewire: this session is on another host; Codewire actions run cw on this machine", 0)
    end
  end

  -- `args.env` as given, else nothing: cw then uses the selected environment.
  local function env_arg(args)
    local env = args and args.env or ""
    if type(env) ~= "string" then return "" end
    return env
  end

  -- The selected environment's ID, read when the action runs.
  local function current()
    local result = rex.exec({ cw, "current", "--output", "json" }, { timeout = 30 })
    if result == nil or not result.ok then
      local why = result and (result.stderr or "") or ""
      error("codewire: `cw current` failed: " .. why, 0)
    end
    local now = rex.json.decode(result.stdout or "")
    if type(now) ~= "table" or not now.selected then
      error("codewire: no environment is selected. Choose one with Codewire: Choose Environment…", 0)
    end
    return now.id, now.name or now.id
  end

  local function pane(label, command)
    return { block = { flavor = SHELL, label = label, options = { command = command } } }
  end

  -- A pane beside the one the palette was opened from, or a new tab.
  local function open_pane(ctx, label, command)
    local layout = pane(label, command)
    if ctx.block_id == nil then
      local _, err = rex.session.new_window{ label = label, layout = layout, focus = true }
      if err ~= nil then error("codewire: couldn't open a tab: " .. tostring(err), 0) end
      return
    end
    local _, err = rex.session.new_split{
      anchor_id = ctx.block_id,
      direction = "horizontal",
      side = "after",
      focus = true,
      layout = layout,
    }
    if err ~= nil then error("codewire: couldn't open a pane: " .. tostring(err), 0) end
  end

  -- A panel floating over the window; it closes when its program exits.
  local function popover(label, command)
    local _, err = rex.session.new_layer{
      bounds = { 0.2, 0.15, 0.6, 0.5 },
      focus = true,
      layout = pane(label, command),
    }
    if err ~= nil then error("codewire: couldn't open a panel: " .. tostring(err), 0) end
  end

  local function sh(script, ...)
    local argv = { "sh", "-c", script, "cw" }
    for _, part in ipairs({ ... }) do argv[#argv + 1] = part end
    return argv
  end

  local function cw_argv(...)
    local argv = { cw }
    for _, part in ipairs({ ... }) do argv[#argv + 1] = part end
    return argv
  end

  -- The environment and session `cw attach` shows in a block, or nil.
  local function session_in(block_id)
    local status = rex.block.call(TERMINAL, "program_status", { block_id = block_id })
    if type(status) ~= "table" or type(status.records) ~= "table" then return nil end
    local record
    for _, r in ipairs(status.records) do
      if r.id == RECORD then record = r end
    end
    if record == nil or type(record.title) ~= "string" then return nil end
    local info = rex.block.call(TERMINAL, "process", { block_id = block_id })
    local front = type(info) == "table" and info.foreground or nil
    if type(front) ~= "table" or front.name ~= "cw" then return nil end
    local owner = record.owner
    if type(owner) == "table" and owner.pid ~= front.pid then return nil end
    local env, session = record.title:match("^([^/]+)/(.+)$")
    if env == nil then return nil end
    -- While attached, the message says where the environment runs.
    local placement = ({ ["local VM"] = "--local", cloud = "--cloud" })[record.msg] or ""
    return { env = env, session = session, placement = placement }
  end

  -- Running and opening ------------------------------------------------------
  -- With no environment selected these choose one first.

  rex.action{
    name = "codewire_exec",
    title = selected and ("Codewire: Run Once in " .. name .. "…") or "Codewire: Run Once…",
    description = (selected and ("In " .. where .. ". ") or "Choose an environment, then ")
      .. "run a command once in a pane beside you, as `cw exec`: no session is left,"
      .. " and the pane shows how it ended.",
    category = "Codewire",
    keywords = "codewire cw exec once run command test build script",
    args = { command = "string?", env = "string?" },
    run = function(ctx, args)
      local_only(ctx)
      local env = env_arg(args)
      local command = args.command or ""
      local choose = (env == "" and selected == nil) and "1" or "0"
      local label = command:match("^%s*(%S+)") or "once"
      open_pane(ctx, label, sh(ONCE, cw, env, command, choose, env ~= "" and env or where))
    end,
  }

  rex.action{
    name = "codewire_run",
    title = selected and ("Codewire: Start in " .. name .. "…") or "Codewire: Start…",
    description = (selected and ("In " .. where .. ". ") or "Choose an environment, then ")
      .. "start something that keeps running, such as a server or an agent, as a"
      .. " session in a pane beside you. claude or codex opens that agent's own terminal UI.",
    category = "Codewire",
    keywords = "codewire cw run command session agent claude codex server test",
    args = { command = "string?", env = "string?" },
    run = function(ctx, args)
      local_only(ctx)
      local env = env_arg(args)
      local command = args.command or ""
      local choose = (env == "" and selected == nil) and "1" or "0"
      local label = command:match("^%s*(%S+)") or "run"
      open_pane(ctx, label, sh(RUN, cw, env, command, choose, env ~= "" and env or where))
    end,
  }

  rex.action{
    name = "codewire_shell",
    title = selected and ("Codewire: Open Shell in " .. name) or "Codewire: Open Shell…",
    description = (selected and ("In " .. where .. ": ") or "Choose an environment, then open ")
      .. "a login shell in a new session beside you.",
    category = "Codewire",
    keywords = "codewire cw shell terminal ssh login",
    args = { env = "string?" },
    run = function(ctx, args)
      local_only(ctx)
      local env = env_arg(args)
      if env ~= "" then
        open_pane(ctx, "shell", cw_argv("shell", env))
      elseif selected then
        open_pane(ctx, "shell", cw_argv("shell"))
      else
        open_pane(ctx, "shell", sh(CHOOSE_THEN, cw, "shell"))
      end
    end,
  }

  rex.action{
    name = "codewire_use",
    title = "Codewire: Choose Environment…",
    description = (selected and ("Now " .. where .. ". ") or "None is chosen yet. ")
      .. "Choose the environment Codewire actions use, or create one.",
    category = "Codewire",
    keywords = "codewire cw use select switch create environment picker",
    run = function(ctx)
      local_only(ctx)
      popover("Environment", cw_argv("use"))
    end,
  }

  rex.action{
    name = "codewire_ls",
    title = "Codewire: List Environments",
    description = "List your local, cloud and host environments with their state and sessions.",
    category = "Codewire",
    keywords = "codewire cw ls list environments sessions inventory",
    run = function(ctx)
      local_only(ctx)
      popover("Environments", sh(SHOW, cw, "ls"))
    end,
  }

  -- With an environment selected ------------------------------------------

  if selected then
    rex.action{
      name = "codewire_attach",
      title = "Codewire: Attach to a Session in " .. name .. "…",
      description = "Attach to a session of " .. where .. " in a pane beside you:"
        .. " its only session, a choice among them, or a new shell.",
      category = "Codewire",
      keywords = "codewire cw attach session reconnect resume",
      args = { env = "string?", session = "string?" },
      run = function(ctx, args)
        local_only(ctx)
        local env, label = env_arg(args), nil
        if env == "" then env, label = current() end
        local argv = cw_argv("attach", env)
        if type(args.session) == "string" and args.session ~= "" then
          argv[#argv + 1] = "--session"
          argv[#argv + 1] = args.session
        end
        open_pane(ctx, args.session or label or env, argv)
      end,
    }

    rex.action{
      name = "codewire_msg",
      title = "Codewire: Message This Session…",
      description = "Send a message to the Codewire session attached in the focused pane:"
        .. " typed into its terminal, or a managed agent's next task.",
      category = "Codewire",
      keywords = "codewire cw msg message send agent task prompt",
      run = function(ctx)
        local_only(ctx)
        local here = ctx.block_id and session_in(ctx.block_id) or nil
        if here == nil then
          error("codewire: the focused pane isn't attached to a Codewire session", 0)
        end
        popover("Message", sh(MSG, cw, here.env, here.session, here.placement))
      end,
    }
  end

  if sandbox then
    rex.action{
      name = "codewire_ports",
      title = "Codewire: Ports of " .. name,
      description = "List the ports " .. where .. " publishes.",
      category = "Codewire",
      keywords = "codewire cw ports preview url publish",
      args = { env = "string?" },
      run = function(ctx, args)
        local_only(ctx)
        local env = env_arg(args)
        if env ~= "" then
          popover("Ports", sh(SHOW, cw, "ports", env))
        else
          popover("Ports", sh(SHOW, cw, "ports"))
        end
      end,
    }

    rex.action{
      name = "codewire_vscode",
      title = "Codewire: Open " .. name .. " in VS Code",
      description = "Open " .. where .. " in VS Code through Remote-SSH.",
      category = "Codewire",
      keywords = "codewire cw vscode code editor remote ssh",
      args = { env = "string?" },
      run = function(ctx, args)
        local_only(ctx)
        local argv = cw_argv("vscode")
        local env = env_arg(args)
        if env ~= "" then argv[#argv + 1] = env end
        local _, err = rex.exec.start(argv, { detach = true })
        if err ~= nil then error("codewire: couldn't start cw vscode: " .. tostring(err), 0) end
      end,
    }
  end
end

return M
