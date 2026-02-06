from typing import Dict
from bs4 import BeautifulSoup
import logging

logger = logging.getLogger(__name__)


class HTMLExtractor:
    def __init__(self):
        self.clickable_selectors = [
            'a[href]',
            'button',
            'input[type="button"]',
            'input[type="submit"]',
            '[onclick]',
            '[role="button"]',
            '[tabindex]:not([tabindex="-1"])'
        ]
    
    def extract_body_and_clickable_elements(self, html_content: str) -> str:
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            body = soup.find('body')
            if not body:
                logger.warning("No body tag found in HTML content")
                return ""
            simplified_html = self._create_simplified_html(body)
            
            return simplified_html
            
        except Exception as e:
            logger.error(f"Error extracting HTML content: {e}")
            return html_content
    
    def _create_simplified_html(self, body) -> str:
        main_content = self._extract_main_content(body)
        clickable_elements = self._extract_clickable_elements_with_context(body)
        simplified_html = "<html><body>"
        if main_content:
            simplified_html += f"<div class='main-content'>{main_content}</div>"
        if clickable_elements:
            simplified_html += "<div class='clickable-elements'>"
            simplified_html += "<h3>Clickable Elements:</h3>"
            simplified_html += clickable_elements
            simplified_html += "</div>"
        
        simplified_html += "</body></html>"
        
        return simplified_html
    
    def _extract_main_content(self, body) -> str:
        """Extract main content areas, prioritizing common content containers"""
        content_selectors = [
            'main',
            '[role="main"]',
            'article',
            '.content',
            '.main-content',
            '#content',
            '#main'
        ]
        
        for selector in content_selectors:
            content = body.select_one(selector)
            if content:
                return self._clean_text_content(str(content))
        paragraphs = body.find_all('p', limit=5)
        if paragraphs:
            return ''.join([self._clean_text_content(str(p)) for p in paragraphs])
        
        return ""
    
    def _extract_clickable_elements_with_context(self, body) -> str:
        clickable_html = ""
        
        for selector in self.clickable_selectors:
            elements = body.select(selector)
            
            for element in elements:
                element_info = self._extract_element_info(element)
                if element_info:
                    clickable_html += f"<div class='clickable-element'>{element_info}</div>"
        
        return clickable_html
    
    def _extract_element_info(self, element) -> str:

        tag_name = element.name.lower()
        element_html = f"<{tag_name}"
        important_attrs = ['href', 'onclick', 'role', 'type', 'name', 'id', 'class']
        for attr in important_attrs:
            if element.has_attr(attr):
                value = element[attr]
                if isinstance(value, list):
                    value = ' '.join(value)
                element_html += f' {attr}="{value}"'
        
        element_html += ">"
        text = element.get_text(strip=True)
        if text:
            text = text[:100] + "..." if len(text) > 100 else text
            element_html += text
        
        element_html += f"</{tag_name}>"
        context = self._get_element_context(element)
        if context:
            element_html += f"<span class='context'> (in {context})</span>"
        
        return element_html
    
    def _get_element_context(self, element, max_depth: int = 3) -> str:
        context_parts = []
        current = element.parent
        depth = 0
        
        while current and depth < max_depth and current.name != 'body':
            if current.name in ['nav', 'header', 'footer', 'aside', 'section', 'div']:
                class_attr = current.get('class', [])
                if class_attr:
                    context_parts.append(f"{current.name}.{'.'.join(class_attr[:2])}")
                else:
                    context_parts.append(current.name)
            current = current.parent
            depth += 1
        
        return " > ".join(reversed(context_parts))
    
    def _clean_text_content(self, html_content: str) -> str:
        soup = BeautifulSoup(html_content, 'html.parser')
        # Remove all script and style tags
        for script in soup(['script', 'style']):
            script.decompose()
        # Remove comments
        for comment in soup.find_all(string=lambda text: isinstance(text, type(soup.Comment))):
            comment.extract()
        cleaned = str(soup)
        if len(cleaned) > 2000:
            cleaned = cleaned[:2000] + "..."
        
        return cleaned
    
    def extract_search_results_optimized(self, html_content: str, query: str) -> str:
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            search_selectors = [
                '.g',           # Google search results
                '.search-result',
                '.result',
                '[data-ved]',   # Google search results
                '.rc',          # Google search results
                '.tF2Cxc',      # Google search results
                '.yuRUbf'       # Google search results
            ]
            
            search_results = []
            
            for selector in search_selectors:
                results = soup.select(selector)
                for result in results:
                    result_info = self._extract_search_result_info(result)
                    if result_info:
                        search_results.append(result_info)
            if not search_results:
                return self.extract_body_and_clickable_elements(html_content)
            formatted_results = f"<html><body><h2>Search Results for: {query}</h2>"
            
            for i, result in enumerate(search_results, 1):
                formatted_results += f"<div class='search-result' data-index='{i}'>"
                formatted_results += f"<div class='title'>{result.get('title', '')}</div>"
                formatted_results += f"<div class='url'>{result.get('url', '')}</div>"
                formatted_results += f"<div class='snippet'>{result.get('snippet', '')}</div>"
                formatted_results += "</div>"
            
            formatted_results += "</body></html>"
            
            return formatted_results
            
        except Exception as e:
            logger.error(f"Error extracting search results: {e}")
            return self.extract_body_and_clickable_elements(html_content)
    
    def _extract_search_result_info(self, result_element) -> Dict[str, str]:
        info = {
            'title': '',
            'url': '',
            'snippet': ''
        }
    
        title_selectors = ['h3', 'h2', '.title', '[role="heading"]']
        for selector in title_selectors:
            title_elem = result_element.select_one(selector)
            if title_elem:
                info['title'] = title_elem.get_text(strip=True)
                break
        
        link_elem = result_element.select_one('a[href]')
        if link_elem and link_elem.has_attr('href'):
            info['url'] = link_elem['href']
        
        snippet_selectors = ['.snippet', '.s', '.VwiC3b', '.yDYNvb', '[data-sncf]']
        for selector in snippet_selectors:
            snippet_elem = result_element.select_one(selector)
            if snippet_elem:
                info['snippet'] = snippet_elem.get_text(strip=True)
                break
        if info['title'] or info['url']:
            return info
        
        return None


def extract_body_and_clickable_elements(html_content: str) -> str:
    extractor = HTMLExtractor()
    return extractor.extract_body_and_clickable_elements(html_content)


def extract_search_results_optimized(html_content: str, query: str) -> str:
    extractor = HTMLExtractor()
    return extractor.extract_search_results_optimized(html_content, query)
