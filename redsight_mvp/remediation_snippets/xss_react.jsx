// before
<div dangerouslySetInnerHTML={{__html: user.bio}} />

// after - escape or sanitize
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(user.bio)}} />
