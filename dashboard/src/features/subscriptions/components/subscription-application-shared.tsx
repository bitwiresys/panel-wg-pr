import { Apple, HelpCircle, Laptop, Monitor, Smartphone, Tv } from 'lucide-react'

/** Safe HTTP(S) icon URL for app logos (blocks javascript:/data:). */
export function isValidIconUrl(url: string): boolean {
  if (!url || url.trim() === '') return false
  try {
    const urlObj = new URL(url)
    if (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:') return false
    const normalizedUrl = url.toLowerCase().trim()
    if (normalizedUrl.includes('javascript:') || normalizedUrl.includes('data:')) return false
    return true
  } catch {
    return false
  }
}

export const platformOptions = [
  { value: 'android', label: 'settings.subscriptions.applications.platforms.android' },
  { value: 'ios', label: 'settings.subscriptions.applications.platforms.ios' },
  { value: 'windows', label: 'settings.subscriptions.applications.platforms.windows' },
  { value: 'macos', label: 'settings.subscriptions.applications.platforms.macos' },
  { value: 'linux', label: 'settings.subscriptions.applications.platforms.linux' },
  { value: 'appletv', label: 'settings.subscriptions.applications.platforms.appletv' },
  { value: 'androidtv', label: 'settings.subscriptions.applications.platforms.androidtv' },
] as const

// Same platform set as `platformOptions`, plus "unknown" for clients that don't send
// a device OS header — used by the host "Device OS" filter, not the Applications form.
export const hostPlatformOptions = [...platformOptions, { value: 'unknown', label: 'settings.subscriptions.applications.platforms.unknown' }] as const

export const languageOptions = [
  { value: 'en', label: 'English', icon: '🇺🇸' },
  { value: 'fa', label: 'فارسی', icon: '🇮🇷' },
  { value: 'ru', label: 'Русский', icon: '🇷🇺' },
  { value: 'zh', label: '中文', icon: '🇨🇳' },
] as const

export function PlatformIcon({ platform }: { platform: string }) {
  switch (platform) {
    case 'android':
    case 'ios':
      return <Smartphone className="h-3.5 w-3.5" />
    case 'macos':
      return <Apple className="h-3.5 w-3.5" />
    case 'windows':
      return <Laptop className="h-3.5 w-3.5" />
    case 'linux':
      return <Monitor className="h-3.5 w-3.5" />
    case 'appletv':
    case 'androidtv':
      return <Tv className="h-3.5 w-3.5" />
    case 'unknown':
      return <HelpCircle className="h-3.5 w-3.5" />
    default:
      return <Monitor className="h-3.5 w-3.5" />
  }
}
