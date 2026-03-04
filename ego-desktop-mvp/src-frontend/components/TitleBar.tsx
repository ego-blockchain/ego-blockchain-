import React from 'react';
import { appWindow } from '@tauri-apps/api/window';

const TitleBar: React.FC = () => {
  return (
    <div
      className="flex items-center h-9 bg-gray-900 border-b border-gray-800 shrink-0 select-none"
      style={{ WebkitUserSelect: 'none' }}
    >
      {/* Traffic-light buttons */}
      <div className="flex items-center gap-[6px] pl-3 pr-4 group">
        {/* Red — Close */}
        <button
          onClick={() => appWindow.close()}
          className="w-3 h-3 rounded-full flex items-center justify-center transition-opacity"
          style={{ backgroundColor: '#ff5f57' }}
          title="Close"
        >
          <svg
            className="w-[7px] h-[7px] opacity-0 group-hover:opacity-100 transition-opacity"
            viewBox="0 0 10 10"
            fill="none"
          >
            <path d="M2 2l6 6M8 2l-6 6" stroke="#820005" strokeWidth="1.5" strokeLinecap="round" />
          </svg>
        </button>

        {/* Yellow — Minimize */}
        <button
          onClick={() => appWindow.minimize()}
          className="w-3 h-3 rounded-full flex items-center justify-center transition-opacity"
          style={{ backgroundColor: '#ffbd2e' }}
          title="Minimize"
        >
          <svg
            className="w-[7px] h-[7px] opacity-0 group-hover:opacity-100 transition-opacity"
            viewBox="0 0 10 10"
            fill="none"
          >
            <path d="M2 5h6" stroke="#9d5800" strokeWidth="1.5" strokeLinecap="round" />
          </svg>
        </button>

        {/* Green — Maximize */}
        <button
          onClick={() => appWindow.toggleMaximize()}
          className="w-3 h-3 rounded-full flex items-center justify-center transition-opacity"
          style={{ backgroundColor: '#28c840' }}
          title="Maximize"
        >
          <svg
            className="w-[7px] h-[7px] opacity-0 group-hover:opacity-100 transition-opacity"
            viewBox="0 0 10 10"
            fill="none"
          >
            <path d="M2 5h6M5 2v6" stroke="#0a5516" strokeWidth="1.5" strokeLinecap="round" />
          </svg>
        </button>
      </div>

      {/* Drag region + title */}
      <div
        data-tauri-drag-region
        className="flex-1 h-full flex items-center justify-center"
      >
        <span className="text-xs text-gray-500 font-medium pointer-events-none">
          Ego Desktop
        </span>
      </div>

      {/* Right spacer (mirrors button width to keep title centred) */}
      <div className="w-[60px] shrink-0" />
    </div>
  );
};

export default TitleBar;
