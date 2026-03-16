// --- DOM ELEMENTS ---
const menuToggle = document.getElementById('menu-toggle');
const sideDrawer = document.getElementById('side-drawer');
const sidebarOverlay = document.getElementById('sidebar-overlay');
const profileBtn = document.getElementById('profile-btn');
const profileDropdown = document.getElementById('profile-dropdown');
const viewProfileBtn = document.getElementById('view-profile-btn'); 
const dropdownLoginBtn = document.getElementById('dropdown-login-btn');
const dropdownLogoutBtn = document.getElementById('dropdown-logout-btn');
const createPostBtn = document.getElementById('create-post-btn');
const closeButtons = document.querySelectorAll('.btn-close, .modal-close'); 
const sendOtpBtn = document.getElementById('send-otp');
const authModal = document.getElementById('auth-modal');
const otpSection = document.getElementById('otp-section');
const userEmailInput = document.getElementById('user-email');
const verifyBtn = document.getElementById('verify-btn');
const otpInput = document.getElementById('otp-code');

// Page Containers
const feedContainer = document.getElementById('feed-container'); 
const mainFeed = document.getElementById('main-feed-list'); 
const createPostPage = document.getElementById('create-post-page');
const postDetailPage = document.getElementById('post-detail-page');
const editProfilePage = document.getElementById('edit-profile-page'); 
const singlePostContainer = document.getElementById('single-post-container');

// Buttons
const cancelPostBtn = document.getElementById('cancel-post-btn');
const backToFeedBtn = document.getElementById('back-to-feed-btn');
const backFromEditBtn = document.getElementById('back-from-edit-btn');
const publishBtn = document.getElementById('publish-post-btn');
const titleInput = document.getElementById('new-post-title');
const titleCounter = document.getElementById('title-counter');
const editorTabs = document.querySelectorAll('.editor-tabs .tab');
const tabContents = document.querySelectorAll('.tab-content');
const toolbarButtons = document.querySelectorAll('.tool-btn');
const editorContent = document.getElementById('editor-content');
const customUploadBtn = document.getElementById('custom-upload-btn');
const realFileInput = document.getElementById('real-file-input');
const uploadText = document.getElementById('upload-text');

function showPage(pageId) {
    if (feedContainer) feedContainer.style.display = 'none';
    if (createPostPage) createPostPage.style.display = 'none';
    if (postDetailPage) postDetailPage.style.display = 'none';
    if (editProfilePage) editProfilePage.style.display = 'none';
    
    const target = document.getElementById(pageId);
    if (target) target.style.display = 'block';
}

const toBase64 = file => new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.readAsDataURL(file);
    reader.onload = () => resolve(reader.result);
    reader.onerror = error => reject(error);
});

function updateProfileUI() {
    const token = localStorage.getItem('uniToken');
    const savedEmail = localStorage.getItem('userEmail');

    if (savedEmail && savedEmail.trim().toLowerCase() === "mishradivyajyoti178@gmail.com") {
        const adminBtn = document.getElementById('admin-panel-btn');
        if (adminBtn) adminBtn.style.display = 'flex';
    }

    if (token && savedEmail) {
        try {
            const payload = JSON.parse(atob(token.split('.')[1]));
            const realUsername = payload.username || 'u/' + savedEmail.split('@')[0];
            const otherProfileNames = document.querySelectorAll('.profile-username');
            otherProfileNames.forEach(el => el.innerText = realUsername);
            const profileEmailText = document.querySelectorAll('.profile-email');
            profileEmailText.forEach(el => el.innerText = savedEmail);
        } catch (error) {}
    }
}

async function loadAllPosts() {
    try {
        const response = await fetch('https://unithread-backend.onrender.com/api/posts?t=' + new Date().getTime());
        const data = await response.json();

        if (data.success) {
            let myVotes = {};
            try { myVotes = JSON.parse(localStorage.getItem('myVotes')) || {}; } catch(e){}

            if (mainFeed) mainFeed.innerHTML = '';

            data.posts.reverse().forEach(post => {
                const postDate = new Date(post.created_at).toLocaleDateString();
                let imageHTML = '';
                if (post.image_data) {
                    imageHTML = `<img src="${post.image_data}" style="width: 100%; border-radius: 8px; margin-top: 15px; border: 1px solid var(--border-2);">`;
                }

                const upDisabled = myVotes[post.id] === 'up' ? 'upvoted' : '';
                const dropDisabled = myVotes[post.id] === 'drop' ? 'downvoted' : '';
                const scoreColor = upDisabled ? 'upvoted-score' : (dropDisabled ? 'downvoted-score' : '');

                // 🚨 NEW: Removed side column, moved voting to the footer with hollow arrows
                const newPostHTML = `
                    <div class="post-card" data-id="${post.id}">
                        <div class="post-body">
                            <div class="post-meta">
                                <span class="flair flair-cyan">#CampusLife</span>
                                <span class="meta-dot">•</span>
                                <span class="meta-author">Posted by <span>${post.author}</span></span>
                                <span class="meta-time">${postDate}</span>
                            </div>
                            <h2 class="post-title">${post.title}</h2>
                            <div class="post-excerpt">${post.content}</div>
                            ${imageHTML}
                            <div class="post-footer" style="margin-top: 16px;">
                                
                                <div class="inline-vote">
                                    <button class="vote-btn up-btn ${upDisabled}">
                                        <svg width="18" height="18" viewBox="0 0 24 24" class="vote-icon"><path d="M12 3l8 10h-5v8H9v-8H4z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/></svg>
                                    </button>
                                    <span class="vote-score ${scoreColor}">${post.score || 1}</span>
                                    <button class="vote-btn drop-btn ${dropDisabled}">
                                        <svg width="18" height="18" viewBox="0 0 24 24" class="vote-icon"><path d="M12 21l-8-10h5V3h6v8h5z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/></svg>
                                    </button>
                                </div>

                                <button class="footer-btn">
                                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"></path></svg>
                                    Comments
                                </button>
                                <button class="footer-btn delete-post-btn" style="color: var(--red); margin-left: auto;">
                                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
                                    Delete
                                </button>
                            </div>
                        </div>
                    </div>
                `;
                
                if (mainFeed) mainFeed.insertAdjacentHTML('beforeend', newPostHTML);
            });

            setTimeout(() => {
                document.querySelectorAll('.post-card').forEach(card => card.classList.add('visible'));
            }, 50);

            showPage('feed-container');
        }
    } catch (error) { console.error("Error loading feed:", error); }
}

document.addEventListener('DOMContentLoaded', () => {
    const isLoggedIn = localStorage.getItem('isLoggedIn');
    if (isLoggedIn !== 'true') {
        setTimeout(() => { if(authModal) authModal.classList.add('open'); }, 500);
    } else {
        updateProfileUI(); 
        if (typeof syncProfileFromCloud === 'function') syncProfileFromCloud();
    }
    loadAllPosts();
});

// --- NAVIGATION LISTENERS ---
createPostBtn.addEventListener('click', () => showPage('create-post-page'));
cancelPostBtn.addEventListener('click', () => showPage('feed-container'));
backToFeedBtn.addEventListener('click', () => { showPage('feed-container'); currentOpenPostId = null; });
if (backFromEditBtn) backFromEditBtn.addEventListener('click', () => showPage('feed-container'));

// --- MENU & MODAL LISTENERS ---
menuToggle.addEventListener('click', (e) => { 
    e.stopPropagation(); 
    sideDrawer.classList.toggle('open'); 
    menuToggle.classList.toggle('open');
    if(sidebarOverlay) sidebarOverlay.classList.toggle('show');
});

if(sidebarOverlay) {
    sidebarOverlay.addEventListener('click', () => {
        sideDrawer.classList.remove('open'); menuToggle.classList.remove('open'); sidebarOverlay.classList.remove('show');
    });
}

profileBtn.addEventListener('click', (e) => { e.stopPropagation(); profileDropdown.classList.toggle('open'); });
dropdownLoginBtn.addEventListener('click', () => { profileDropdown.classList.remove('open'); if(authModal) authModal.classList.add('open'); });
dropdownLogoutBtn.addEventListener('click', () => { 
    localStorage.removeItem('isLoggedIn'); localStorage.removeItem('uniToken'); localStorage.removeItem('userEmail'); window.location.reload(); 
});
closeButtons.forEach(btn => { 
    btn.addEventListener('click', () => { 
        if(authModal) authModal.classList.remove('open'); 
        const draftsModal = document.getElementById('drafts-modal'); if(draftsModal) draftsModal.classList.remove('open');
        const adminModal = document.getElementById('admin-modal'); if(adminModal) adminModal.classList.remove('open');
    }); 
});
window.addEventListener('click', (e) => {
    if (profileDropdown.classList.contains('open') && !profileDropdown.contains(e.target) && !profileBtn.contains(e.target)) { 
        profileDropdown.classList.remove('open'); 
    }
});

// --- PUBLISH POST LOGIC ---
publishBtn.addEventListener('click', async () => {
    const title = titleInput.value.trim();
    let content = editorContent.innerHTML.trim(); 
    const file = realFileInput.files[0];
    const linkUrl = document.querySelector('#link-tab input[type="url"]').value.trim();
    const linkTitle = document.querySelector('#link-tab textarea').value.trim() || linkUrl;
    const pollInputs = document.querySelectorAll('#poll-tab input[type="text"]');
    const opt1 = pollInputs[0].value.trim(); const opt2 = pollInputs[1].value.trim();

    if (linkUrl) content += `<div style="margin-top: 15px; padding: 12px; background: var(--bg-mid); border-radius: 8px; border: 1px solid var(--border-2);">🔗 <a href="${linkUrl}" target="_blank" style="color: var(--accent-bright); text-decoration: none;">${linkTitle}</a></div>`;
    if (opt1 && opt2) content += `<div class="poll-container"><h4 style="margin-bottom: 10px;">📊 Poll</h4><div class="poll-option">○ ${opt1}</div><div class="poll-option">○ ${opt2}</div></div>`;

    publishBtn.innerText = "Publishing..."; publishBtn.disabled = true;
    const myToken = localStorage.getItem('uniToken');

    try {
        let base64Image = null;
        if (file) base64Image = await toBase64(file);
        const response = await fetch('https://unithread-backend.onrender.com/api/posts', {
            method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${myToken}` },
            body: JSON.stringify({ title: title, content: content, image_data: base64Image })
        });
        const data = await response.json();
        if (data.success) {
            titleInput.value = ''; editorContent.innerHTML = ''; titleCounter.innerText = '0/300'; realFileInput.value = '';
            if(uploadText) uploadText.innerText = 'Drag and drop images or videos here';
            document.querySelector('#link-tab input[type="url"]').value = ''; document.querySelector('#link-tab textarea').value = '';
            pollInputs[0].value = ''; pollInputs[1].value = '';
            loadAllPosts(); 
        } else { alert("Failed to save post."); }
    } catch (error) { console.error("Error saving post:", error); } 
    finally { publishBtn.innerText = "Publish Post"; publishBtn.disabled = false; }
});

// --- COMMENTS ---
async function loadComments(postId) {
    const commentsList = document.getElementById('comments-list');
    commentsList.innerHTML = '<div class="no-comments"><p>Loading comments...</p></div>';
    try {
        const response = await fetch(`https://unithread-backend.onrender.com/api/posts/${postId}/comments`);
        const data = await response.json();
        if (data.success && data.comments.length > 0) {
            commentsList.innerHTML = ''; 
            data.comments.forEach(comment => {
                const date = new Date(comment.created_at).toLocaleDateString();
                commentsList.innerHTML += `
                    <div class="comment-item">
                        <div class="comment-inner">
                            <div class="comment-left">
                                <img src="https://api.dicebear.com/9.x/avataaars/svg?seed=Felix&backgroundColor=6366f1" class="comment-avatar">
                            </div>
                            <div class="comment-content">
                                <div class="comment-meta">
                                    <span class="comment-author">${comment.author}</span>
                                    <span class="comment-time">${date}</span>
                                </div>
                                <div class="comment-body">${comment.content}</div>
                            </div>
                        </div>
                    </div>`;
            });
        } else { commentsList.innerHTML = '<div class="no-comments"><p>No comments yet. Be the first to share your thoughts!</p></div>'; }
    } catch (error) { commentsList.innerHTML = '<div class="auth-error">Failed to load comments.</div>'; }
}

const addCommentBtn = document.getElementById('add-comment-btn');
const newCommentInput = document.getElementById('new-comment-input');
let currentOpenPostId = null;

if (addCommentBtn) {
    addCommentBtn.addEventListener('click', async () => {
        const content = newCommentInput.value.trim();
        if (!content || !currentOpenPostId) return;

        addCommentBtn.innerText = "Posting..."; addCommentBtn.disabled = true;
        const myToken = localStorage.getItem('uniToken');

        try {
            const response = await fetch(`https://unithread-backend.onrender.com/api/posts/${currentOpenPostId}/comments`, {
                method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${myToken}` },
                body: JSON.stringify({ content: content }) 
            });
            const data = await response.json();
            if (data.success) { newCommentInput.value = ''; loadComments(currentOpenPostId); } 
            else { alert("Failed to post comment."); }
        } catch (error) { alert("Failed to post comment."); } 
        finally { addCommentBtn.innerText = "Post Comment"; addCommentBtn.disabled = false; }
    });
}

// 🚨 NEW: Universal Voting Logic (Works everywhere!)
document.body.addEventListener('click', async (e) => {
    const upBtn = e.target.closest('.up-btn');
    const dropBtn = e.target.closest('.drop-btn');
    
    if (upBtn || dropBtn) {
        e.stopPropagation();
        const postCard = (upBtn || dropBtn).closest('.post-card');
        if (!postCard) return;
        
        const postId = postCard.getAttribute('data-id');
        const scoreSpan = postCard.querySelector('.vote-score');
        if (scoreSpan.innerText === "...") return;

        let myVotes = {};
        try { myVotes = JSON.parse(localStorage.getItem('myVotes')) || {}; } catch(err){}
        
        // 🚨 STRICT LOCK: Prevents multiple votes!
        if (myVotes[postId]) {
            alert("You have already voted on this post!");
            return; 
        }

        const action = upBtn ? 'up' : 'drop';
        const originalScore = scoreSpan.innerText;
        scoreSpan.innerText = "...";
        const myToken = localStorage.getItem('uniToken');

        try {
            const response = await fetch(`https://unithread-backend.onrender.com/api/posts/${postId}/vote`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${myToken}` },
                body: JSON.stringify({ action: action })
            });
            const data = await response.json();
            if (data.success) {
                scoreSpan.innerText = data.newScore;
                (upBtn || dropBtn).classList.add(action === 'up' ? 'upvoted' : 'downvoted');
                scoreSpan.classList.add(action === 'up' ? 'upvoted-score' : 'downvoted-score');
                myVotes[postId] = action; 
                localStorage.setItem('myVotes', JSON.stringify(myVotes)); 
            } else { scoreSpan.innerText = originalScore; }
        } catch (error) { scoreSpan.innerText = originalScore; }
        return;
    }
});

// Opening Posts & Deleting
if(mainFeed) {
    mainFeed.addEventListener('click', async (e) => {
        const deleteBtn = e.target.closest('.delete-post-btn');
        if (deleteBtn) {
            const postCard = deleteBtn.closest('.post-card');
            const postId = postCard.getAttribute('data-id'); 
            if (confirm("Are you sure you want to delete this post?")) {
                const myToken = localStorage.getItem('uniToken');
                try {
                    const response = await fetch(`https://unithread-backend.onrender.com/api/posts/${postId}`, { 
                        method: 'DELETE', headers: { 'Authorization': `Bearer ${myToken}` } 
                    });
                    const result = await response.json();
                    if (result.success) {
                        postCard.style.opacity = '0';
                        setTimeout(() => postCard.remove(), 300);
                    }
                } catch (error) { console.error("Delete failed:", error); }
            }
            return; 
        }
        
        // Prevent opening if clicking inside inline-vote or polls
        if (e.target.closest('.inline-vote') || e.target.classList.contains('poll-option') || e.target.tagName === 'A') return;
        
        const postCard = e.target.closest('.post-card');
        if (postCard) {
            currentOpenPostId = postCard.getAttribute('data-id');
            showPage('post-detail-page');
            singlePostContainer.innerHTML = postCard.outerHTML;
            singlePostContainer.querySelector('.post-card').style.cursor = 'default';
            const innerDelete = singlePostContainer.querySelector('.delete-post-btn');
            if (innerDelete) innerDelete.style.display = 'none';
            loadComments(currentOpenPostId);
        }
    });
}

// --- CREATE POST EXTRAS ---
titleInput.addEventListener('input', () => {
    const len = titleInput.value.length; titleCounter.innerText = `${len}/300`;
    if (len > 0) { publishBtn.disabled = false; publishBtn.style.opacity = '1'; publishBtn.style.cursor = 'pointer'; } 
    else { publishBtn.disabled = true; publishBtn.style.opacity = '0.5'; publishBtn.style.cursor = 'not-allowed'; }
});
editorTabs.forEach(tab => {
    tab.addEventListener('click', () => {
        editorTabs.forEach(t => t.classList.remove('active')); tabContents.forEach(c => c.style.display = 'none');
        tab.classList.add('active'); document.getElementById(tab.getAttribute('data-target')).style.display = 'block';
    });
});
toolbarButtons.forEach(btn => {
    btn.addEventListener('click', (e) => {
        e.preventDefault(); const command = btn.getAttribute('data-command');
        if (command === 'createLink') { const url = prompt('Enter the link URL:', 'https://'); if (url) document.execCommand(command, false, url); } 
        else { document.execCommand(command, false, null); }
        editorContent.focus();
    });
});
if(customUploadBtn) {
    customUploadBtn.addEventListener('click', () => realFileInput.click());
    realFileInput.addEventListener('change', () => {
        if (realFileInput.files.length > 0) {
            uploadText.innerText = `Selected: ${realFileInput.files[0].name}`; uploadText.style.color = 'var(--accent-bright)'; customUploadBtn.innerText = "Change File";
        }
    });
}
document.body.addEventListener('click', (e) => {
    if (e.target.classList.contains('poll-option')) {
        const container = e.target.closest('.poll-container');
        container.querySelectorAll('.poll-option').forEach(opt => {
            opt.style.background = 'var(--bg-surface)'; opt.style.borderColor = 'var(--border-2)'; opt.innerText = opt.innerText.replace('●', '○');
        });
        e.target.style.background = 'var(--accent-subtle)'; e.target.style.borderColor = 'var(--accent-border)'; e.target.innerText = e.target.innerText.replace('○', '●');
    }
});

// --- OTP & AUTH ---
sendOtpBtn.addEventListener('click', async () => {
    const email = userEmailInput.value.trim();
    if (email.endsWith('.edu') || email.includes('.ac.in') || email.endsWith('@gmail.com')) {
        sendOtpBtn.innerText = "Sending..."; sendOtpBtn.disabled = true;
        try {
            const response = await fetch('https://unithread-backend.onrender.com/send-otp', {
                method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: email })
            });
            const result = await response.json();
            if (result.success) { alert("Verification code sent to " + email); otpSection.style.display = 'block'; } 
            else { alert("Server error: " + result.message); }
        } catch (error) { alert("Could not connect to the server."); } 
        finally { sendOtpBtn.innerText = "Send OTP"; sendOtpBtn.disabled = false; }
    } else { alert("Access Denied: Please use your official University Email ID."); }
});
const profileSetupSection = document.getElementById('profile-setup-section');
const setupUsernameInput = document.getElementById('setup-username');
const setupCourseInput = document.getElementById('setup-course');
const setupYearInput = document.getElementById('setup-year');
const submitProfileBtn = document.getElementById('submit-profile-btn');
let tempRegistrationEmail = ""; 
verifyBtn.addEventListener('click', async () => {
    const email = userEmailInput.value; const otp = otpInput.value;
    try {
        const response = await fetch('https://unithread-backend.onrender.com/verify-otp', {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, otp })
        });
        const result = await response.json();
        if (response.status === 403) { alert("⏳ " + result.message); return; }
        if (result.success) {
            if (result.isNewUser) {
                document.querySelector('.input-group').style.display = 'none'; otpSection.style.display = 'none'; 
                document.getElementById('auth-title').innerText = "Create Your Identity"; profileSetupSection.style.display = 'block';
                tempRegistrationEmail = result.email; 
            } else {
                authModal.classList.remove('open'); localStorage.setItem('isLoggedIn', 'true'); 
                localStorage.setItem('uniToken', result.token); localStorage.setItem('userEmail', email);
                updateProfileUI(); window.location.reload(); 
            }
        } else { alert("❌ " + result.message); }
    } catch (error) { alert("Error verifying OTP."); }
});
if (submitProfileBtn) {
    submitProfileBtn.addEventListener('click', async () => {
        const username = setupUsernameInput.value.trim(); const course = setupCourseInput.value.trim(); const year = setupYearInput.value.trim();
        if (!username || !course || !year) { alert("Please fill in all fields!"); return; }
        submitProfileBtn.innerText = "Submitting..."; submitProfileBtn.disabled = true;
        try {
            const response = await fetch('https://unithread-backend.onrender.com/api/setup-profile', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: tempRegistrationEmail, username: username, course: course, year: year })
            });
            const result = await response.json();
            if (result.success) {
                alert("✅ Application submitted! Wait for Admin approval.");
                authModal.classList.remove('open'); profileSetupSection.style.display = 'none'; 
                const updatedProfile = { course: course, year: year, avatar: '' };
                localStorage.setItem('uniProfile', JSON.stringify(updatedProfile));
            } else { alert("❌ " + result.message); }
        } catch (error) { alert("Error submitting profile."); } 
        finally { submitProfileBtn.innerText = "Submit Application"; submitProfileBtn.disabled = false; }
    });
}

// --- PROFILE EDIT ---
const editCourseInput = document.getElementById('edit-course-input');
const editYearInput = document.getElementById('edit-year-input');
const profilePicUpload = document.getElementById('profile-pic-upload');
const editAvatarPreview = document.getElementById('edit-avatar-preview');
const saveFullProfileBtn = document.getElementById('save-full-profile-btn');

const applyProfileData = () => {
    try {
        const savedProfile = JSON.parse(localStorage.getItem('uniProfile'));
        if (savedProfile) {
            const userYearSpan = document.getElementById('user-year'); if (userYearSpan) userYearSpan.innerText = savedProfile.year || 'N/A';
            if (savedProfile.avatar) {
                const allAvatars = document.querySelectorAll('.nav-avatar, .pd-big-avatar, .comment-composer-avatar, .pf-avatar, .comment-avatar');
                allAvatars.forEach(img => img.src = savedProfile.avatar);
                if (editAvatarPreview) editAvatarPreview.src = savedProfile.avatar;
            }
        }
    } catch (err) {}
};
applyProfileData();

async function syncProfileFromCloud() {
    const myToken = localStorage.getItem('uniToken');
    if (!myToken) return;
    try {
        const response = await fetch('https://unithread-backend.onrender.com/api/profile', { headers: { 'Authorization': `Bearer ${myToken}` } });
        const data = await response.json();
        if (data.success && data.profile) {
            const cloudProfile = {
                course: data.profile.course || 'BCA / IT', year: data.profile.year || '1st Year',
                avatar: data.profile.avatar_url || 'https://api.dicebear.com/9.x/avataaars/svg?seed=Felix&backgroundColor=6366f1'
            };
            localStorage.setItem('uniProfile', JSON.stringify(cloudProfile)); applyProfileData();
        }
    } catch (error) { }
}

const settingsBtn = document.getElementById('settings-btn');

function openProfilePage(e) {
    // Stop the click from closing the dropdown immediately and messing up the event
    if(e) {
        e.preventDefault();
        e.stopPropagation();
    }
    
    console.log("🛠️ DEBUG: Opening Edit Profile Page!");
    
    if(profileDropdown) profileDropdown.classList.remove('open');
    
    try {
        const savedProfile = JSON.parse(localStorage.getItem('uniProfile'));
        if (savedProfile) {
            if (editCourseInput) editCourseInput.value = savedProfile.course || '';
            if (editYearInput) editYearInput.value = savedProfile.year || '';
        }
    } catch(err) {
        console.log("No profile data found in local storage");
    }
    
    // Explicitly call our showPage function
    showPage('edit-profile-page');
}

// Ensure the listeners are explicitly attached
if (viewProfileBtn) {
    viewProfileBtn.addEventListener('click', openProfilePage);
}
if (settingsBtn) {
    settingsBtn.addEventListener('click', openProfilePage);
}
if (profilePicUpload) {
    profilePicUpload.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (file) { const base64Image = await toBase64(file); editAvatarPreview.src = base64Image; }
    });
}
if (saveFullProfileBtn) {
    saveFullProfileBtn.addEventListener('click', async () => {
        saveFullProfileBtn.innerText = "Saving..."; saveFullProfileBtn.disabled = true;
        const myToken = localStorage.getItem('uniToken');
        const courseStr = editCourseInput.value.trim(); const yearStr = editYearInput.value.trim();
        const avatarData = editAvatarPreview.src.startsWith('data:image') ? editAvatarPreview.src : null;
        try {
            const response = await fetch('https://unithread-backend.onrender.com/api/profile', {
                method: 'PUT', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${myToken}` },
                body: JSON.stringify({ course: courseStr, year: yearStr, avatar_data: avatarData })
            });
            const data = await response.json();
            if (data.success) {
                const savedProfile = JSON.parse(localStorage.getItem('uniProfile')) || {};
                savedProfile.course = courseStr; savedProfile.year = yearStr;
                if (data.avatar_url) savedProfile.avatar = data.avatar_url;
                localStorage.setItem('uniProfile', JSON.stringify(savedProfile)); applyProfileData();
                saveFullProfileBtn.innerText = "✅ Saved!";
                setTimeout(() => { saveFullProfileBtn.innerText = "Save Changes"; saveFullProfileBtn.disabled = false; showPage('feed-container'); }, 1000);
            }
        } catch (error) { saveFullProfileBtn.innerText = "Save Changes"; saveFullProfileBtn.disabled = false; }
    });
}

// --- DRAFTS & ADMIN LOGIC ---
const saveDraftBtn = document.getElementById('save-draft-btn');
const draftLink = document.querySelector('.draft-link');
const draftsModal = document.getElementById('drafts-modal');
const closeDraftsBtn = document.getElementById('close-drafts-btn');
const draftsListContainer = document.getElementById('drafts-list-container');
if (saveDraftBtn) {
    saveDraftBtn.addEventListener('click', (e) => {
        e.preventDefault(); const title = titleInput.value.trim(); const content = editorContent.innerHTML.trim();
        if (!title && !content) return;
        const newDraft = { id: Date.now(), title: title || "Untitled", content: content, date: new Date().toLocaleDateString() };
        let drafts = []; try { drafts = JSON.parse(localStorage.getItem('uniThreadDrafts')) || []; } catch(err){}
        drafts.push(newDraft); localStorage.setItem('uniThreadDrafts', JSON.stringify(drafts));
        const originalText = saveDraftBtn.innerText; saveDraftBtn.innerText = "✅ Saved!";
        setTimeout(() => saveDraftBtn.innerText = originalText, 1500);
    });
}
if (draftLink) {
    draftLink.addEventListener('click', () => {
        let drafts = []; try { drafts = JSON.parse(localStorage.getItem('uniThreadDrafts')) || []; } catch(err){}
        if (drafts.length === 0) { alert("No saved drafts."); return; }
        draftsListContainer.innerHTML = '';
        drafts.reverse().forEach(draft => {
            const draftHTML = `<div class="draft-item"><div><h4>${draft.title}</h4><span>${draft.date}</span></div><div style="display: flex; gap: 10px;"><button class="btn-ghost load-draft-btn" data-id="${draft.id}" style="padding: 4px 12px;">Load</button><button class="btn-ghost delete-draft-btn" data-id="${draft.id}" style="padding: 4px 12px; color: var(--red);">Delete</button></div></div>`;
            draftsListContainer.insertAdjacentHTML('beforeend', draftHTML);
        });
        draftsModal.classList.add('open');
    });
}
if (draftsListContainer) {
    draftsListContainer.addEventListener('click', (e) => {
        const loadBtn = e.target.closest('.load-draft-btn'); const deleteBtn = e.target.closest('.delete-draft-btn');
        let drafts = []; try { drafts = JSON.parse(localStorage.getItem('uniThreadDrafts')) || []; } catch(err){}
        if (loadBtn) {
            const selectedDraft = drafts.find(d => d.id == loadBtn.getAttribute('data-id'));
            if (selectedDraft) {
                titleInput.value = selectedDraft.title === "Untitled" ? "" : selectedDraft.title; editorContent.innerHTML = selectedDraft.content || '';
                titleCounter.innerText = `${titleInput.value.length}/300`;
                if (titleInput.value.length > 0) { publishBtn.disabled = false; publishBtn.style.opacity = '1'; }
                draftsModal.classList.remove('open');
            }
        }
        if (deleteBtn) {
            drafts = drafts.filter(d => d.id != deleteBtn.getAttribute('data-id')); localStorage.setItem('uniThreadDrafts', JSON.stringify(drafts));
            deleteBtn.closest('.draft-item').remove(); if (drafts.length === 0) draftsModal.classList.remove('open');
        }
    });
}
if (closeDraftsBtn) closeDraftsBtn.addEventListener('click', () => draftsModal.classList.remove('open'));

const adminPanelBtn = document.getElementById('admin-panel-btn');
const adminModal = document.getElementById('admin-modal');
const closeAdminBtn = document.getElementById('close-admin-btn');
const pendingUsersList = document.getElementById('pending-users-list');
if (adminPanelBtn) { adminPanelBtn.addEventListener('click', () => { if(profileDropdown) profileDropdown.classList.remove('open'); adminModal.classList.add('open'); loadPendingUsers(); }); }
if (closeAdminBtn) closeAdminBtn.addEventListener('click', () => adminModal.classList.remove('open'));
async function loadPendingUsers() {
    if (!pendingUsersList) return; pendingUsersList.innerHTML = '<div class="no-comments"><p>Loading...</p></div>';
    const myToken = localStorage.getItem('uniToken');
    try {
        const response = await fetch('https://unithread-backend.onrender.com/api/admin/pending', { headers: { 'Authorization': `Bearer ${myToken}` } });
        const data = await response.json();
        if (data.success) {
            if (data.users.length === 0) { pendingUsersList.innerHTML = '<div class="no-comments"><p style="color: var(--green);">✅ All caught up!</p></div>'; return; }
            pendingUsersList.innerHTML = '';
            data.users.forEach(user => {
                pendingUsersList.insertAdjacentHTML('beforeend', `<div class="draft-item" style="flex-direction: column; align-items: stretch; gap: 10px;"><div><h4>${user.username}</h4><span style="display:block; margin-bottom: 2px;">${user.email}</span><span>${user.course} | ${user.year} | Applied: ${new Date(user.created_at).toLocaleDateString()}</span></div><div style="display: flex; gap: 10px;"><button class="btn-submit approve-btn" data-email="${user.email}" style="flex:1; padding: 6px; background: var(--green);">Approve</button><button class="btn-ghost reject-btn" data-email="${user.email}" style="flex:1; padding: 6px; color: var(--red); border-color: var(--red);">Reject</button></div></div>`);
            });
        } else { pendingUsersList.innerHTML = `<div class="auth-error">${data.message}</div>`; }
    } catch (error) { pendingUsersList.innerHTML = '<div class="auth-error">Failed to load applications.</div>'; }
}
if (pendingUsersList) {
    pendingUsersList.addEventListener('click', async (e) => {
        const approveBtn = e.target.closest('.approve-btn'); const rejectBtn = e.target.closest('.reject-btn');
        if (!approveBtn && !rejectBtn) return;
        const action = approveBtn ? 'approved' : 'rejected'; const email = (approveBtn || rejectBtn).getAttribute('data-email');
        const btn = approveBtn || rejectBtn; const originalText = btn.innerText; btn.innerText = "..."; btn.disabled = true;
        const myToken = localStorage.getItem('uniToken');
        try {
            const response = await fetch('https://unithread-backend.onrender.com/api/admin/moderate', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${myToken}` }, body: JSON.stringify({ email, action }) });
            const data = await response.json();
            if (data.success) { loadPendingUsers(); } else { alert("Failed: " + data.message); btn.innerText = originalText; btn.disabled = false; }
        } catch (err) { alert("Error."); btn.innerText = originalText; btn.disabled = false; }
    });
}

// --- 🌙 LIGHT/DARK THEME TOGGLE LOGIC ---
const themeToggleBtn = document.getElementById('theme-toggle-btn');
const htmlElement = document.documentElement;
const savedTheme = localStorage.getItem('unithreadTheme') || 'dark';
htmlElement.setAttribute('data-theme', savedTheme);
if (themeToggleBtn) {
    themeToggleBtn.addEventListener('click', () => {
        const currentTheme = htmlElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        htmlElement.setAttribute('data-theme', newTheme); localStorage.setItem('unithreadTheme', newTheme);
    });
}