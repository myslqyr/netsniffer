#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo '请使用 sudo bash scripts/install-capture-helper.sh 执行安装。' >&2
    exit 1
fi

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
build_dir=${1:-"${project_dir}/build"}
capture_user=${SUDO_USER:-}
if [[ -z ${capture_user} || ${capture_user} == root ]]; then
    echo '请从日常开发用户通过 sudo 执行，不能直接在 root 会话中安装。' >&2
    exit 1
fi
capture_group=$(id -g -- "${capture_user}")
source_binary="${build_dir}/netsniffer-capture"
destination_dir=/usr/local/libexec/netsniffer
destination="${destination_dir}/netsniffer-capture"

for command in install mktemp setcap getcap; do
    if ! command -v "${command}" >/dev/null; then
        echo "缺少命令：${command}；setcap/getcap 由 libcap2-bin 提供。" >&2
        exit 1
    fi
done
if [[ ! -f ${source_binary} || ! -x ${source_binary} ]]; then
    echo "请先编译辅助程序：${source_binary}" >&2
    exit 1
fi
# Never install a privileged executable through a symbolic-link destination.
for component in /usr/local /usr/local/libexec "${destination_dir}" "${destination}"; do
    if [[ -L ${component} ]]; then
        echo "安装目标不能是符号链接：${component}" >&2
        exit 1
    fi
done
install -d -o root -g root -m 0755 /usr/local/libexec "${destination_dir}"
temporary=$(mktemp "${destination_dir}/.capture.XXXXXX")
trap 'rm -f -- "${temporary}"' EXIT
install -o root -g "${capture_group}" -m 0750 -- "${source_binary}" "${temporary}"
setcap cap_net_raw=ep "${temporary}"
mv -f -- "${temporary}" "${destination}"

# Remove any capability granted to the former all-in-one GUI.
gui_binary="${build_dir}/netsniffer"
if [[ -f ${gui_binary} && ! -L ${gui_binary} ]] && [[ -n $(getcap "${gui_binary}") ]]; then
    setcap -r "${gui_binary}"
fi
echo "已安装：${destination}"
echo "可执行用户：root 和 ${capture_user} 的主组（GID ${capture_group}）"
getcap "${destination}"
echo '界面程序无需管理员权限。后续重新编译界面后无需再次安装。'
