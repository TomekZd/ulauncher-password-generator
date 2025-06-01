import logging
import hashlib
import threading
import time
import subprocess
from ulauncher.api.client.Extension import Extension
from ulauncher.api.client.EventListener import EventListener
from ulauncher.api.shared.event import KeywordQueryEvent, ItemEnterEvent
from ulauncher.api.shared.item.ExtensionResultItem import ExtensionResultItem
from ulauncher.api.shared.action.SetUserQueryAction import SetUserQueryAction
from ulauncher.api.shared.action.RenderResultListAction import RenderResultListAction
from ulauncher.api.shared.action.ExtensionCustomAction import ExtensionCustomAction
from ulauncher.api.shared.action.HideWindowAction import HideWindowAction
from ulauncher.api.shared.action.CopyToClipboardAction import CopyToClipboardAction
from ulauncher.api.shared.action.DoNothingAction import DoNothingAction

logger = logging.getLogger(__name__)

class SecureCopyToClipboardAction(CopyToClipboardAction):
    """Enhanced clipboard action that auto-clears after timeout"""
    
    def __init__(self, text, clear_after_seconds=10):
        super().__init__(text)
        self.text = text
        self.clear_after_seconds = clear_after_seconds
    
    def keep_app_alive(self):
        """Override to handle clipboard clearing"""
        result = super().keep_app_alive()
        # Start the auto-clear timer
        self._start_clear_timer()
        return result
    
    def _start_clear_timer(self):
        """Start a timer to clear clipboard after specified seconds"""
        def clear_clipboard():
            time.sleep(self.clear_after_seconds)
            try:
                # Check if our password is still in clipboard before clearing
                current_clipboard = self._get_clipboard_content()
                if current_clipboard == self.text:
                    self._clear_clipboard()
                    logger.info(f"Clipboard cleared after {self.clear_after_seconds} seconds")
            except Exception as e:
                logger.error(f"Failed to clear clipboard: {e}")
        
        # Run in daemon thread so it doesn't prevent app exit
        timer_thread = threading.Thread(target=clear_clipboard, daemon=True)
        timer_thread.start()
    
    def _get_clipboard_content(self):
        """Get current clipboard content"""
        try:
            # Try xclip first (most common on Linux)
            result = subprocess.run(['xclip', '-selection', 'clipboard', '-o'], 
                                  capture_output=True, text=True, timeout=1)
            if result.returncode == 0:
                return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        try:
            # Fallback to xsel
            result = subprocess.run(['xsel', '--clipboard', '--output'], 
                                  capture_output=True, text=True, timeout=1)
            if result.returncode == 0:
                return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        return ""
    
    def _clear_clipboard(self):
        """Clear the clipboard"""
        try:
            # Try xclip first
            subprocess.run(['xclip', '-selection', 'clipboard'], 
                          input='', text=True, timeout=1)
            return
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        try:
            # Fallback to xsel
            subprocess.run(['xsel', '--clipboard', '--clear'], timeout=1)
            return
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        try:
            # Another fallback - set clipboard to empty string
            subprocess.run(['xclip', '-selection', 'clipboard'], 
                          input=' ', text=True, timeout=1)
        except:
            logger.error("Could not clear clipboard - no suitable tool found")

class PasswordGeneratorExtention(Extension):

    def __init__(self):
        super(PasswordGeneratorExtention, self).__init__()
        self.subscribe(KeywordQueryEvent, KeywordQueryEventListener())

class KeywordQueryEventListener(EventListener):

    def on_event(self, event, extension):
        items = []
        user_input = event.get_argument() or ""

        if user_input != "":
            queries = user_input.split(' ')
            key = queries[0]
            
            mode = extension.preferences['charlist']
            length = -1
            exclude = ""
            include = ""
            clear_timeout = 10  # Default 10 seconds
            
            if len(queries) > 1:
                for i in range(1, len(queries)):
                    query = queries[i].lower()
                    if query.startswith('mode:') or query.startswith('m:'):
                        m = query.split(':')[1]
                        if m=='alphanumeric' or m=='an':
                            mode = 'alphanumeric'
                        elif m=='loweralphanumeric' or m=='lower' or m=='lan' or m=='ln':
                            mode = 'loweralphanumeric'
                        elif m=='alphabets' or m=='ab':
                            mode = 'alphabets'
                        elif m=='all' :
                            mode = 'all'
                    elif query.startswith('length:') or query.startswith('len:') or query.startswith('l:'):
                        try:
                            length = int(query.split(':')[1])
                        except Exception:
                            length = -1
                    elif query.startswith('exclude:') or query.startswith('e:') or query.startswith('ex:'):
                        exclude = query.split(':')[1]
                    elif query.startswith('include:') or query.startswith('in:') or query.startswith('i:'):
                        include = query.split(':')[1]
                    elif query.startswith('clear:') or query.startswith('c:'):
                        try:
                            clear_timeout = int(query.split(':')[1])
                        except Exception:
                            clear_timeout = 10
            
            password_generator = PasswordGenerator(extension.preferences['password_namespace'], extension.preferences['password_header'])
            password = password_generator.generate(key, length, mode, exclude, include)

            # Use the enhanced clipboard action with auto-clear
            clipboard_action = SecureCopyToClipboardAction(password, clear_timeout)
            
            description = f'Press Enter to copy (auto-clear after {clear_timeout}s)'
            items.append(ExtensionResultItem(
                icon='images/icon.png',
                name=password,
                description=description,
                on_enter=clipboard_action
            ))

        return RenderResultListAction(items)

def RenderError(error):
    items = []
    items.append(ExtensionResultItem(icon='images/error.png',
            name=error['title'],
            description=error['description'],
            on_enter=DoNothingAction()))
    return items

class PasswordGenerator:

    def __init__(self, namespace, head):
        self.namespace = hashlib.sha256(namespace.encode('utf-8')).hexdigest()
        self.password_head = head

    def generate(self, key, length=-1, mode='all', exclude="", include=""):
        plaintext_password = self.password_head + key
        hashed_password = hashlib.sha256(plaintext_password.encode('utf-8')).hexdigest()

        merged = self.namespace + ':' + hashed_password
        merged = hashlib.sha512(merged.encode('utf-8')).hexdigest()
        password = self.convert(int(merged, 16), mode, exclude, include)

        if length == -1:
            return password
        return password[:length]
    
    def convert(self, number, mode='default', exclude="", include=""):
        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !#$%&()*+,-./:;=?@[\]^_`{|}~'
        if mode == 'alphanumeric':
            chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        elif mode == 'loweralphanumeric':
            chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
        elif mode == 'alphabets':
            chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
        
        if exclude != "":
            for char in exclude:
                chars = chars.replace(char, '')
        
        if include != "":
            for char in include:
                if char not in chars:
                    chars += char

        return self.convert_to_base(number, chars)

    def convert_to_base(self, number, chars):
        base = len(chars)
        if number < base:
            return chars[number]
        else:
            new_number = number // base
            remainder = number % base
            return self.convert_to_base(new_number, chars) + chars[remainder]

if __name__ == '__main__':
    PasswordGeneratorExtention().run()
