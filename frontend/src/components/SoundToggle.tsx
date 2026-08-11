import React from 'react';
import { Volume2, VolumeX } from 'lucide-react';
import { useToast } from '../context/ToastContext';

const SoundToggle: React.FC<{ className?: string }> = ({ className = '' }) => {
  const { soundEnabled, toggleSound } = useToast();
  return (
    <button
      onClick={toggleSound}
      aria-label={soundEnabled ? 'Mute critical alert sound' : 'Unmute critical alert sound'}
      title={soundEnabled ? 'Mute critical alert sound' : 'Unmute critical alert sound'}
      className={`p-2 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 rounded-md transition-colors ${className}`}
    >
      {soundEnabled ? <Volume2 className="w-4 h-4" /> : <VolumeX className="w-4 h-4" />}
    </button>
  );
};

export default SoundToggle;
