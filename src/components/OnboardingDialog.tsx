import { useState } from "react";
import {
  BookOpenText,
  ChevronLeft,
  ChevronRight,
  CircleHelp,
  CircleStop,
  Download,
  FolderOpen,
  Image,
  KeyRound,
  Package,
  Pencil,
  Play,
  Plus,
  RadioTower,
  Search,
  Server,
  Settings2,
  SquareTerminal,
  Trash2,
  Upload,
} from "lucide-react";
import { Dialog } from "./Dialog";

interface OnboardingDialogProps {
  onClose: () => void;
}

const steps = [
  {
    title: "添加或导入主机",
    icon: Server,
    location: "左侧“主机”",
    description: "点右上角 + 添加主机；点下载图标从 FinalShell 导入。导入密码可由直连终端、负载采样和 SFTP 自动使用。",
    actions: [
      { icon: Plus, label: "添加", meaning: "新建一台 SSH 主机" },
      { icon: Download, label: "导入", meaning: "迁移 FinalShell 配置和可识别密码" },
      { icon: Trash2, label: "删除", meaning: "移入可恢复 30 天的回收站" },
    ],
  },
  {
    title: "连接与多标签",
    icon: SquareTerminal,
    location: "顶部标签与“连接”按钮",
    description: "选择主机后点“连接”。每台主机保留独立标签，顶部始终显示当前用户、IP 和环境，断开按钮只影响当前标签。",
    actions: [
      { icon: Play, label: "连接", meaning: "启动当前主机的真实 SSH 终端" },
      { icon: CircleStop, label: "断开", meaning: "仅断开当前标签" },
      { icon: Plus, label: "新标签", meaning: "打开新的主机会话标签" },
    ],
  },
  {
    title: "传输与编辑文件",
    icon: FolderOpen,
    location: "终端下方“SFTP 文件”",
    description: "浏览当前远端路径，把文件或文件夹拖入面板即可上传；选择远端内容可下载，双击文本文件可用 Notepad++ 或设置的编辑器打开。",
    actions: [
      { icon: Upload, label: "上传", meaning: "选择文件或文件夹，也支持直接拖入" },
      { icon: Download, label: "下载", meaning: "下载当前选中的远端内容" },
      { icon: Pencil, label: "外部编辑", meaning: "用 Notepad++ 或指定编辑器安全回传" },
      { icon: Package, label: "打包传输", meaning: "大量小文件使用 tar + zstd" },
    ],
  },
  {
    title: "命令、脚本与广播",
    icon: BookOpenText,
    location: "左侧命令库/脚本中心与底部命令栏",
    description: "搜索想做的事并先核对最终命令。打开广播后勾选目标终端，目标会持续保留，直到你主动取消或关闭会话。",
    actions: [
      { icon: Search, label: "搜索", meaning: "按用途查找命令或脚本" },
      { icon: RadioTower, label: "广播", meaning: "持续选择多个会话并发送同一命令" },
      { icon: Play, label: "执行", meaning: "向当前或已勾选终端发送命令" },
    ],
  },
  {
    title: "外观、升级与帮助",
    icon: Settings2,
    location: "右上角图片、设置和帮助按钮",
    description: "图片按钮设置终端背景；设置按钮选择外部编辑器并检查升级；问号按钮可随时重新打开本指南。",
    actions: [
      { icon: Image, label: "外观", meaning: "背景图片、字体和字号" },
      { icon: KeyRound, label: "密钥", meaning: "生成和安装 SSH 密钥" },
      { icon: Settings2, label: "设置", meaning: "编辑器设置与检查升级" },
      { icon: CircleHelp, label: "帮助", meaning: "随时重新打开本指南" },
    ],
  },
] as const;

export function OnboardingDialog({ onClose }: OnboardingDialogProps) {
  const [index, setIndex] = useState(0);
  const step = steps[index];
  const StepIcon = step.icon;
  const last = index === steps.length - 1;

  return (
    <Dialog
      title="VPShell 使用指南"
      wide
      onClose={onClose}
      footer={(
        <>
          <button className="secondary-button" type="button" disabled={index === 0} onClick={() => setIndex((value) => value - 1)}>
            <ChevronLeft size={14} /> 上一步
          </button>
          <span className="guide-footer-spacer" />
          <button className="primary-button" type="button" onClick={() => last ? onClose() : setIndex((value) => value + 1)}>
            {last ? "开始使用" : "下一步"} {!last ? <ChevronRight size={14} /> : null}
          </button>
        </>
      )}
    >
      <div className="guide-progress" aria-label={`第 ${index + 1} 步，共 ${steps.length} 步`}>
        {steps.map((item, itemIndex) => (
          <button
            key={item.title}
            className={itemIndex === index ? "active" : ""}
            type="button"
            title={item.title}
            aria-label={`打开第 ${itemIndex + 1} 步：${item.title}`}
            onClick={() => setIndex(itemIndex)}
          />
        ))}
      </div>
      <section className="guide-step">
        <span className="guide-step-icon"><StepIcon size={26} /></span>
        <div>
          <small>第 {index + 1} / {steps.length} 步</small>
          <h3>{step.title}</h3>
          <strong>{step.location}</strong>
          <p>{step.description}</p>
          <div className="guide-actions">
            {step.actions.map((action) => {
              const ActionIcon = action.icon;
              return (
                <div key={action.label}>
                  <ActionIcon size={15} />
                  <span><b>{action.label}</b><small>{action.meaning}</small></span>
                </div>
              );
            })}
          </div>
        </div>
      </section>
    </Dialog>
  );
}
