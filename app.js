const menuToggle = document.getElementById('menu-toggle');
const sideDrawer = document.getElementById('side-drawer');
const profileBtn = document.getElementById('profile-btn');
const profileDropdown = document.getElementById('profile-dropdown');
const viewProfileBtn = document.getElementById('view-profile-btn');
const dropdownLoginBtn = document.getElementById('dropdown-login-btn');
const dropdownLogoutBtn = document.getElementById('dropdown-logout-btn');
const createPostBtn = document.getElementById('create-post-btn');
const closeButtons = document.querySelectorAll('.btn-close'); 
const sendOtpBtn = document.getElementById('send-otp');
const authModal = document.getElementById('auth-modal');
const profileModal = document.getElementById('profile-modal');
const otpSection = document.getElementById('otp-section');
const userEmailInput = document.getElementById('user-email');
const verifyBtn = document.getElementById('verify-btn');
const otpInput = document.getElementById('otp-code');
const createPostPage = document.getElementById('create-post-page');
const mainFeed = document.querySelector('.feed');
const rightSidebar = document.querySelector('.sidebar-right');
const cancelPostBtn = document.getElementById('cancel-post-btn');
const titleInput = document.getElementById('new-post-title');
const titleCounter = document.getElementById('title-counter');
const publishBtn = document.getElementById('publish-post-btn');
const editorTabs = document.querySelectorAll('.editor-tabs .tab');
const tabContents = document.querySelectorAll('.tab-content');
const toolbarButtons = document.querySelectorAll('.tool-btn');
const editorContent = document.getElementById('editor-content');
const customUploadBtn = document.getElementById('custom-upload-btn');
const realFileInput = document.getElementById('real-file-input');
const uploadText = document.getElementById('upload-text');
const postDetailPage = document.getElementById('post-detail-page');
const backToFeedBtn = document.getElementById('back-to-feed-btn');
const singlePostContainer = document.getElementById('single-post-container');

const toBase64 = file => new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.readAsDataURL(file);
    reader.onload = () => resolve(reader.result);
    reader.onerror = error => reject(error);
});

// 🚨 BULLETPROOF VERSION with Debug Logs
function updateProfileUI() {
    const token = localStorage.getItem('uniToken');
    const savedEmail = localStorage.getItem('userEmail');

    console.log("🛠️ DEBUG: UI Update Started!");
    console.log("🛠️ DEBUG: Email in memory ->", savedEmail);
    console.log("🛠️ DEBUG: Token in memory ->", !!token);

    // 👑 THE ADMIN CHECK (Moved outside so it can't crash!)
    if (savedEmail) {
        if (savedEmail.trim().toLowerCase() === "mishradivyajyoti178@gmail.com") {
            console.log("🛠️ DEBUG: ADMIN DETECTED! Unhiding button...");
            const adminBtn = document.getElementById('admin-panel-btn');
            if (adminBtn) {
                adminBtn.style.display = 'block';
            } else {
                console.log("❌ ERROR: The admin button HTML is missing!");
            }
        } else {
            console.log("🛠️ DEBUG: User is not admin.");
        }
    }

    // Now update the usernames
    if (token && savedEmail) {
        try {
            const payload = JSON.parse(atob(token.split('.')[1]));
            const realUsername = payload.username || 'u/' + savedEmail.split('@')[0];
            
            const profileMuted = document.querySelector('.dropdown-profile-info .text-muted');
            if (profileMuted) profileMuted.innerText = realUsername;
            
            const profileMain = document.querySelector('.dropdown-profile-info h4');
            if (profileMain) profileMain.innerText = realUsername.replace('u/', '');

            const otherProfileNames = document.querySelectorAll('#profile-name, .user-display-name, .profile-username');
            otherProfileNames.forEach(el => el.innerText = realUsername);

            const profileEmailText = document.querySelector('.profile-email');
            if (profileEmailText) profileEmailText.innerText = savedEmail;

        } catch (error) {
            console.error("❌ ERROR decoding token. You might have an old invalid session!", error);
        }
    }
}

async function loadAllPosts() {
    try {
        const response = await fetch('https://unithread-backend.onrender.com/api/posts?t=' + new Date().getTime());
        const data = await response.json();

        if (data.success) {
            let myVotes = {};
            try { myVotes = JSON.parse(localStorage.getItem('myVotes')) || {}; } catch(e){}

            const sortButtons = document.querySelector('.feed-sort');
            const allCurrentPosts = document.querySelectorAll('.feed .post-card');
            allCurrentPosts.forEach(post => post.remove());

            data.posts.reverse().forEach(post => {
                const postDate = new Date(post.created_at).toLocaleDateString();
                let imageHTML = '';
                if (post.image_data) {
                    imageHTML = `<img src="${post.image_data}" style="width: 100%; border-radius: 8px; margin-top: 15px; border: 1px solid var(--border-light);">`;
                }

                const alreadyVotedStyle = myVotes[post.id] ? 'opacity: 0.5; cursor: not-allowed;' : '';

                const newPostHTML = `
                    <div class="post-card" data-id="${post.id}" style="animation: fadeUp 0.5s ease forwards; cursor: pointer; display: block;">
                        <div class="post-body" style="width: 100%;">
                            <div class="post-meta">
                                <span class="tag" style="background: rgba(34, 197, 94, 0.15); color: #22c55e;">#CampusLife</span>
                                <span class="author">Posted by ${post.author} • ${postDate}</span>
                            </div>
                            <h2 class="post-title">${post.title}</h2>
                            <div class="post-excerpt" style="font-size: 0.95rem; color: var(--text-muted); line-height: 1.5; margin-bottom: 16px;">
                                ${post.content}
                            </div>
                            ${imageHTML}
                            <div class="post-footer" style="margin-top: 15px; display: flex; align-items: center; gap: 15px; flex-wrap: wrap;">
                                <div class="vote-actions" style="display: flex; align-items: center; gap: 10px; background: var(--bg-dark); padding: 6px 14px; border-radius: 20px; border: 1px solid var(--border-light); ${alreadyVotedStyle}">
                                    <button class="up-btn" style="background:none; border:none; cursor:pointer; font-size:0.95rem; color: var(--text-muted); display: flex; align-items: center; gap: 5px; transition: 0.2s;">👍 Up</button>
                                    <span class="score" style="font-weight:bold; font-size: 0.95rem; color: var(--text-main);">${post.score || 1}</span>
                                    <button class="drop-btn" style="background:none; border:none; cursor:pointer; font-size:0.95rem; color: var(--text-muted); display: flex; align-items: center; gap: 5px; transition: 0.2s;">👎 Drop</button>
                                </div>
                                <button class="footer-item">💬 Click to View Comments</button>
                                <button class="footer-item delete-post-btn" style="color: #ef4444; margin-left: auto;">🗑️ Delete</button>
                            </div>
                        </div>
                    </div>
                `;
                
                if (sortButtons) {
                    sortButtons.insertAdjacentHTML('afterend', newPostHTML);
                } else if (mainFeed) {
                    mainFeed.insertAdjacentHTML('beforeend', newPostHTML);
                }
            });

            if (mainFeed) mainFeed.style.display = 'block';
            if (rightSidebar) rightSidebar.style.display = 'block';
            if (createPostPage) createPostPage.style.display = 'none';
        }
    } catch (error) {
        console.error("Error loading feed:", error);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const isLoggedIn = localStorage.getItem('isLoggedIn');
    if (isLoggedIn !== 'true') {
        setTimeout(() => authModal.style.display = 'flex', 500);
    } else {
        updateProfileUI(); 
        // 🚨 NEW: Fetch permanent profile on load!
        if (typeof syncProfileFromCloud === 'function') {
            syncProfileFromCloud();
        }
    }
    loadAllPosts();
});

publishBtn.addEventListener('click', async () => {
    const title = titleInput.value.trim();
    let content = editorContent.innerHTML.trim(); 
    const file = realFileInput.files[0];

    const linkUrl = document.querySelector('#link-tab input[type="url"]').value.trim();
    const linkTitle = document.querySelector('#link-tab textarea').value.trim() || linkUrl;
    const pollInputs = document.querySelectorAll('#poll-tab input[type="text"]');
    const opt1 = pollInputs[0].value.trim();
    const opt2 = pollInputs[1].value.trim();

    if (linkUrl) {
        content += `<div style="margin-top: 15px; padding: 12px; background: var(--bg-dark); border-radius: 8px; border: 1px solid var(--border-light);">🔗 <a href="${linkUrl}" target="_blank" style="color: var(--accent-indigo); text-decoration: none; font-weight: 500;">${linkTitle}</a></div>`;
    }

    if (opt1 && opt2) {
        content += `<div class="poll-container" style="margin-top: 15px; padding: 15px; background: var(--bg-dark); border-radius: 8px; border: 1px solid var(--border-light);"><h4 style="margin-bottom: 10px; color: var(--text-main);">📊 Poll</h4><div class="poll-option" style="padding: 10px; border: 1px solid var(--border-light); border-radius: 4px; margin-bottom: 8px; background: var(--bg-card); cursor: pointer; color: var(--text-main); transition: 0.2s;">○ ${opt1}</div><div class="poll-option" style="padding: 10px; border: 1px solid var(--border-light); border-radius: 4px; margin-bottom: 8px; background: var(--bg-card); cursor: pointer; color: var(--text-main); transition: 0.2s;">○ ${opt2}</div></div>`;
    }

    publishBtn.innerText = "Publishing...";
    publishBtn.disabled = true;

    const myToken = localStorage.getItem('uniToken');

    try {
        let base64Image = null;
        if (file) {
            base64Image = await toBase64(file);
        }

        const response = await fetch('https://unithread-backend.onrender.com/api/posts', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${myToken}` 
            },
            body: JSON.stringify({ 
                title: title, 
                content: content, 
                image_data: base64Image
            })
        });

        const data = await response.json();

        if (data.success) {
            titleInput.value = '';
            editorContent.innerHTML = '';
            titleCounter.innerText = '0/300';
            realFileInput.value = '';
            uploadText.innerText = 'Drag and drop images or videos here';
            document.querySelector('#link-tab input[type="url"]').value = '';
            document.querySelector('#link-tab textarea').value = '';
            pollInputs[0].value = '';
            pollInputs[1].value = '';
            
            loadAllPosts(); 
        } else {
            alert("Failed to save post. Did your session expire?");
        }
    } catch (error) {
        console.error("Error saving post:", error);
    } finally {
        publishBtn.innerText = "Post to UniThread";
        publishBtn.disabled = false;
    }
});

async function loadComments(postId) {
    const commentsList = document.getElementById('comments-list');
    commentsList.innerHTML = '<p style="color: var(--text-muted);">Loading comments...</p>';
    try {
        const response = await fetch(`https://unithread-backend.onrender.com/api/posts/${postId}/comments`);
        const data = await response.json();
        if (data.success && data.comments.length > 0) {
            commentsList.innerHTML = ''; 
            data.comments.forEach(comment => {
                const date = new Date(comment.created_at).toLocaleDateString();
                commentsList.innerHTML += `<div style="background: var(--bg-card); padding: 15px; border-radius: 8px; margin-bottom: 10px; border: 1px solid var(--border-light);"><div style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 5px;"><strong>${comment.author}</strong> • ${date}</div><p style="color: var(--text-main); font-size: 0.95rem;">${comment.content}</p></div>`;
            });
        } else {
            commentsList.innerHTML = '<p style="color: var(--text-muted); font-size: 0.9rem;">No comments yet. Be the first to share your thoughts!</p>';
        }
    } catch (error) {
        commentsList.innerHTML = '<p style="color: #ef4444;">Failed to load comments.</p>';
    }
}
const addCommentBtn = document.getElementById('add-comment-btn');
const newCommentInput = document.getElementById('new-comment-input');
let currentOpenPostId = null;

addCommentBtn.addEventListener('click', async () => {
    const content = newCommentInput.value.trim();
    if (!content || !currentOpenPostId) return;

    addCommentBtn.innerText = "Posting...";
    addCommentBtn.disabled = true;
    
    const myToken = localStorage.getItem('uniToken');

    try {
        const response = await fetch(`https://unithread-backend.onrender.com/api/posts/${currentOpenPostId}/comments`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${myToken}` 
            },
            body: JSON.stringify({ content: content }) 
        });

        const data = await response.json();
        if (data.success) {
            newCommentInput.value = '';
            loadComments(currentOpenPostId); 
        } else {
            alert("Failed to post comment. Session may have expired.");
        }
    } catch (error) {
        alert("Failed to post comment.");
    } finally {
        addCommentBtn.innerText = "Comment";
        addCommentBtn.disabled = false;
    }
});

mainFeed.addEventListener('click', async (e) => {
    const deleteBtn = e.target.closest('.delete-post-btn');
    if (deleteBtn) {
        const postCard = deleteBtn.closest('.post-card');
        const postId = postCard.getAttribute('data-id'); 
        if (confirm("Are you sure you want to delete this post?")) {
            
            const myToken = localStorage.getItem('uniToken');
            
            try {
                const response = await fetch(`https://unithread-backend.onrender.com/api/posts/${postId}`, { 
                    method: 'DELETE',
                    headers: { 'Authorization': `Bearer ${myToken}` } 
                });
                
                const result = await response.json();
                if (result.success) {
                    postCard.style.opacity = '0';
                    setTimeout(() => postCard.remove(), 300);
                } else {
                    alert("Delete failed. Unauthorized.");
                }
            } catch (error) {
                console.error("Delete failed:", error);
            }
        }
        return; 
    }
    if (e.target.closest('.up-btn') || e.target.closest('.drop-btn') || e.target.classList.contains('poll-option') || e.target.tagName === 'A') return;
    const postCard = e.target.closest('.post-card');
    if (postCard) {
        currentOpenPostId = postCard.getAttribute('data-id');
        mainFeed.style.display = 'none';
        if(rightSidebar) rightSidebar.style.display = 'none';
        postDetailPage.style.display = 'block';
        singlePostContainer.innerHTML = postCard.outerHTML;
        singlePostContainer.querySelector('.post-card').style.cursor = 'default';
        const innerDelete = singlePostContainer.querySelector('.delete-post-btn');
        if (innerDelete) innerDelete.style.display = 'none';
        loadComments(currentOpenPostId);
    }
});

backToFeedBtn.addEventListener('click', () => {
    postDetailPage.style.display = 'none';
    mainFeed.style.display = 'block';
    if(rightSidebar) rightSidebar.style.display = 'block';
    currentOpenPostId = null;
});

menuToggle.addEventListener('click', (e) => { e.stopPropagation(); sideDrawer.classList.toggle('open'); menuToggle.classList.toggle('active'); });
profileBtn.addEventListener('click', (e) => { e.stopPropagation(); profileDropdown.classList.toggle('show'); });
viewProfileBtn.addEventListener('click', () => { profileDropdown.classList.remove('show'); profileModal.style.display = 'flex'; });
dropdownLoginBtn.addEventListener('click', () => { profileDropdown.classList.remove('show'); authModal.style.display = 'flex'; });

dropdownLogoutBtn.addEventListener('click', () => { 
    localStorage.removeItem('isLoggedIn'); 
    localStorage.removeItem('uniToken'); 
    localStorage.removeItem('userEmail'); 
    window.location.reload(); 
});

createPostBtn.addEventListener('click', () => { mainFeed.style.display = 'none'; if(rightSidebar) rightSidebar.style.display = 'none'; createPostPage.style.display = 'block'; });
cancelPostBtn.addEventListener('click', () => { createPostPage.style.display = 'none'; mainFeed.style.display = 'block'; if(rightSidebar) rightSidebar.style.display = 'block'; });
closeButtons.forEach(btn => { btn.addEventListener('click', () => { authModal.style.display = 'none'; profileModal.style.display = 'none'; }); });

window.addEventListener('click', (e) => {
    if (sideDrawer.classList.contains('open') && !sideDrawer.contains(e.target) && !menuToggle.contains(e.target)) { sideDrawer.classList.remove('open'); menuToggle.classList.remove('active'); }
    if (profileDropdown.classList.contains('show') && !profileDropdown.contains(e.target) && !profileBtn.contains(e.target)) { profileDropdown.classList.remove('show'); }

    if (e.target === authModal) {
        if (localStorage.getItem('isLoggedIn') === 'true') {
            authModal.style.display = 'none';
        } else {
            // Trapped until login
        }
    }

    if (e.target === profileModal) profileModal.style.display = 'none'; 
    if (typeof draftsModal !== 'undefined' && e.target === draftsModal) draftsModal.style.display = 'none';
});

titleInput.addEventListener('input', () => {
    const len = titleInput.value.length;
    titleCounter.innerText = `${len}/300`;
    if (len > 0) { publishBtn.disabled = false; publishBtn.style.opacity = '1'; publishBtn.style.cursor = 'pointer'; } 
    else { publishBtn.disabled = true; publishBtn.style.opacity = '0.5'; publishBtn.style.cursor = 'not-allowed'; }
});

editorTabs.forEach(tab => {
    tab.addEventListener('click', () => {
        editorTabs.forEach(t => t.classList.remove('active'));
        tabContents.forEach(c => c.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById(tab.getAttribute('data-target')).classList.add('active');
    });
});

toolbarButtons.forEach(btn => {
    btn.addEventListener('click', (e) => {
        e.preventDefault(); 
        const command = btn.getAttribute('data-command');
        const value = btn.getAttribute('data-value') || null;
        if (command === 'createLink') {
            const url = prompt('Enter the link URL:', 'https://');
            if (url) document.execCommand(command, false, url);
        } else {
            document.execCommand(command, false, value);
        }
        editorContent.focus();
    });
});

customUploadBtn.addEventListener('click', () => realFileInput.click());
realFileInput.addEventListener('change', () => {
    if (realFileInput.files.length > 0) {
        uploadText.innerText = `Selected: ${realFileInput.files[0].name}`;
        uploadText.style.color = 'var(--accent-indigo)';
        customUploadBtn.innerText = "Change File";
    }
});

document.body.addEventListener('click', async (e) => {
    const upBtn = e.target.closest('.up-btn');
    const dropBtn = e.target.closest('.drop-btn');
    if (!upBtn && !dropBtn) return; 

    const postCard = e.target.closest('.post-card');
    const postId = postCard.getAttribute('data-id');
    const scoreSpan = postCard.querySelector('.score');
    
    if (scoreSpan.innerText === "...") return;

    let myVotes = {};
    try { myVotes = JSON.parse(localStorage.getItem('myVotes')) || {}; } catch(err){}

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
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${myToken}` 
            },
            body: JSON.stringify({ action: action })
        });
        const data = await response.json();

        if (data.success) {
            scoreSpan.innerText = data.newScore;
            scoreSpan.style.color = action === 'up' ? '#22c55e' : '#ef4444';
            setTimeout(() => scoreSpan.style.color = 'var(--text-main)', 1000);

            myVotes[postId] = action; 
            localStorage.setItem('myVotes', JSON.stringify(myVotes)); 
            
            const voteActionsBox = postCard.querySelector('.vote-actions');
            if (voteActionsBox) {
                voteActionsBox.style.opacity = '0.5';
                voteActionsBox.style.cursor = 'not-allowed';
            }
        } else {
            scoreSpan.innerText = originalScore; 
            alert("Vote failed. Unauthorized.");
        }
    } catch (error) {
        scoreSpan.innerText = originalScore;
    }
});

document.body.addEventListener('click', (e) => {
    if (e.target.classList.contains('poll-option')) {
        const container = e.target.closest('.poll-container');
        container.querySelectorAll('.poll-option').forEach(opt => {
            opt.style.background = 'var(--bg-card)';
            opt.style.borderColor = 'var(--border-light)';
            opt.innerText = opt.innerText.replace('●', '○');
        });
        e.target.style.background = 'rgba(99, 102, 241, 0.1)';
        e.target.style.borderColor = 'var(--accent-indigo)';
        e.target.innerText = e.target.innerText.replace('○', '●');
    }
});

sendOtpBtn.addEventListener('click', async () => {
    const email = userEmailInput.value.trim();
    if (email.endsWith('.edu') || email.includes('.ac.in') || email.endsWith('@gmail.com')) {
        sendOtpBtn.innerText = "Sending...";
        sendOtpBtn.disabled = true;
        try {
            const response = await fetch('https://unithread-backend.onrender.com/send-otp', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: email })
            });
            const result = await response.json();
            if (result.success) {
                alert("Verification code sent to " + email);
                otpSection.style.display = 'block'; 
            } else {
                alert("Server error: " + result.message);
            }
        } catch (error) {
            alert("Could not connect to the server.");
        } finally {
            sendOtpBtn.innerText = "Send OTP";
            sendOtpBtn.disabled = false;
        }
    } else {
        alert("Access Denied: Please use your official University Email ID.");
    }
});

const profileSetupSection = document.getElementById('profile-setup-section');
const setupUsernameInput = document.getElementById('setup-username');
const setupCourseInput = document.getElementById('setup-course');
const setupYearInput = document.getElementById('setup-year');
const submitProfileBtn = document.getElementById('submit-profile-btn');
let tempRegistrationEmail = ""; 

verifyBtn.addEventListener('click', async () => {
    const email = userEmailInput.value;
    const otp = otpInput.value;
    try {
        const response = await fetch('https://unithread-backend.onrender.com/verify-otp', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, otp })
        });
        const result = await response.json();

        if (response.status === 403) {
            alert("⏳ " + result.message);
            return;
        }

        if (result.success) {
            if (result.isNewUser) {
            alert("OTP Verified! Please create your profile to join the waitlist.");
            
            document.querySelector('.input-group').style.display = 'none'; 
            otpSection.style.display = 'none'; 
            document.querySelector('.auth-card > p').style.display = 'none';
            document.getElementById('auth-title').innerText = "Create Your Identity";
            
            profileSetupSection.style.display = 'block';
            tempRegistrationEmail = result.email; 
        } else {
                alert("🎉 Welcome back! You are logged in.");
                authModal.style.display = 'none';
                localStorage.setItem('isLoggedIn', 'true'); 
                localStorage.setItem('uniToken', result.token); 
                localStorage.setItem('userEmail', email);
                updateProfileUI();
                window.location.reload(); 
            }
        } else {
            alert("❌ " + result.message);
        }
    } catch (error) {
        alert("Error verifying OTP.");
    }
});

if (submitProfileBtn) {
    submitProfileBtn.addEventListener('click', async () => {
        const username = setupUsernameInput.value.trim();
        const course = setupCourseInput.value.trim();
        const year = setupYearInput.value.trim();

        if (!username || !course || !year) {
            alert("Please fill in all fields!");
            return;
        }

        submitProfileBtn.innerText = "Submitting...";
        submitProfileBtn.disabled = true;

        try {
            const response = await fetch('https://unithread-backend.onrender.com/api/setup-profile', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    email: tempRegistrationEmail,
                    username: username,
                    course: course,
                    year: year
                })
            });
            const result = await response.json();

            if (result.success) {
                alert("✅ Application submitted! Please wait for the Admin to approve your account.");
                authModal.style.display = 'none';
                profileSetupSection.style.display = 'none'; 
                
                const updatedProfile = { course: course, year: year, avatar: '' };
                localStorage.setItem('uniProfile', JSON.stringify(updatedProfile));

            } else {
                alert("❌ " + result.message);
            }
        } catch (error) {
            alert("Error submitting profile.");
        } finally {
            submitProfileBtn.innerText = "Submit Application";
            submitProfileBtn.disabled = false;
        }
    });
}

// ==========================================
// --- 4. EDIT PROFILE LOGIC ---
// ==========================================
const editProfileBtn = document.getElementById('edit-profile-btn');
const editProfilePage = document.getElementById('edit-profile-page');
const backFromEditBtn = document.getElementById('back-from-edit-btn');
const saveFullProfileBtn = document.getElementById('save-full-profile-btn');

const userCourseSpan = document.getElementById('user-course');
const userYearSpan = document.getElementById('user-year');
const editCourseInput = document.getElementById('edit-course-input');
const editYearInput = document.getElementById('edit-year-input');

const profilePicUpload = document.getElementById('profile-pic-upload');
const editAvatarPreview = document.getElementById('edit-avatar-preview');

const applyProfileData = () => {
    const savedProfile = JSON.parse(localStorage.getItem('uniProfile'));
    if (savedProfile) {
        if (userCourseSpan) userCourseSpan.innerText = savedProfile.course || 'BCA / IT';
        if (userYearSpan) userYearSpan.innerText = savedProfile.year || '3rd Year';
        if (savedProfile.avatar) {
            const allAvatars = document.querySelectorAll('.profile-icon img, .dropdown-avatar, .post-profile-selector img, .profile-large-avatar');
            allAvatars.forEach(img => img.src = savedProfile.avatar);
            if (editAvatarPreview) editAvatarPreview.src = savedProfile.avatar;
        }
    }
};

applyProfileData();

// 🚨 NEW: Download permanent profile from the database!
async function syncProfileFromCloud() {
    const myToken = localStorage.getItem('uniToken');
    if (!myToken) return;

    try {
        const response = await fetch('https://unithread-backend.onrender.com/api/profile', {
            headers: { 'Authorization': `Bearer ${myToken}` }
        });
        const data = await response.json();

        if (data.success && data.profile) {
            // Update local storage with the official database info
            const cloudProfile = {
                course: data.profile.course || 'BCA / IT',
                year: data.profile.year || '1st Year',
                avatar: data.profile.avatar_url || 'https://api.dicebear.com/9.x/avataaars/svg?seed=Felix&backgroundColor=6366f1' // Default avatar
            };
            localStorage.setItem('uniProfile', JSON.stringify(cloudProfile));
            
            // Re-apply the visuals instantly!
            applyProfileData();
        }
    } catch (error) {
        console.error("Failed to sync profile from cloud:", error);
    }
}

if (editProfileBtn) {
    editProfileBtn.addEventListener('click', () => {
        profileModal.style.display = 'none';
        mainFeed.style.display = 'none';
        if(rightSidebar) rightSidebar.style.display = 'none';
        createPostPage.style.display = 'none';
        postDetailPage.style.display = 'none';
        editProfilePage.style.display = 'block';
        editCourseInput.value = userCourseSpan.innerText;
        editYearInput.value = userYearSpan.innerText;
    });
}

if (profilePicUpload) {
    profilePicUpload.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (file) {
            const base64Image = await toBase64(file);
            editAvatarPreview.src = base64Image; 
        }
    });
}
if (saveFullProfileBtn) {
    saveFullProfileBtn.addEventListener('click', async () => {
        saveFullProfileBtn.innerText = "Saving to Cloud...";
        saveFullProfileBtn.disabled = true;

        const myToken = localStorage.getItem('uniToken');
        const courseStr = editCourseInput.value.trim();
        const yearStr = editYearInput.value.trim();
        // Only send image data if it's a NEW base64 upload, not an existing HTTP link
        const avatarData = editAvatarPreview.src.startsWith('data:image') ? editAvatarPreview.src : null;

        try {
            const response = await fetch('https://unithread-backend.onrender.com/api/profile', {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${myToken}`
                },
                body: JSON.stringify({
                    course: courseStr,
                    year: yearStr,
                    avatar_data: avatarData
                })
            });

            const data = await response.json();

            if (data.success) {
                // Update local storage so the UI updates instantly
                const savedProfile = JSON.parse(localStorage.getItem('uniProfile')) || {};
                savedProfile.course = courseStr;
                savedProfile.year = yearStr;
                if (data.avatar_url) savedProfile.avatar = data.avatar_url;
                
                localStorage.setItem('uniProfile', JSON.stringify(savedProfile));
                applyProfileData();

                saveFullProfileBtn.innerText = "✅ Saved!";
                setTimeout(() => {
                    saveFullProfileBtn.innerText = "Save Changes";
                    saveFullProfileBtn.disabled = false;
                    editProfilePage.style.display = 'none';
                    mainFeed.style.display = 'block';
                    if(rightSidebar) rightSidebar.style.display = 'block';
                }, 1000);
            } else {
                alert("Failed to save profile: " + data.message);
                saveFullProfileBtn.innerText = "Save Changes";
                saveFullProfileBtn.disabled = false;
            }
        } catch (error) {
            console.error("Profile save error", error);
            alert("Network error. Could not save profile.");
            saveFullProfileBtn.innerText = "Save Changes";
            saveFullProfileBtn.disabled = false;
        }
    });
}

if (backFromEditBtn) {
    backFromEditBtn.addEventListener('click', () => {
        editProfilePage.style.display = 'none';
        mainFeed.style.display = 'block';
        if(rightSidebar) rightSidebar.style.display = 'block';
    });
}

// ==========================================
// --- 5. MULTIPLE DRAFTS LOGIC ---
// ==========================================
const saveDraftBtn = document.getElementById('save-draft-btn');
const draftLink = document.querySelector('.draft-link');
const draftsModal = document.getElementById('drafts-modal');
const closeDraftsBtn = document.getElementById('close-drafts-btn');
const draftsListContainer = document.getElementById('drafts-list-container');

if (saveDraftBtn) {
    saveDraftBtn.addEventListener('click', (e) => {
        e.preventDefault();
        const title = titleInput.value.trim();
        const content = editorContent.innerHTML.trim();

        if (!title && !content) {
            alert("Nothing to save!");
            return;
        }

        const newDraft = {
            id: Date.now(),
            title: title || "Untitled Draft",
            content: content,
            date: new Date().toLocaleDateString() + ' ' + new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})
        };

        let drafts = JSON.parse(localStorage.getItem('uniThreadDrafts')) || [];
        drafts.push(newDraft);
        localStorage.setItem('uniThreadDrafts', JSON.stringify(drafts));

        const originalText = saveDraftBtn.innerText;
        saveDraftBtn.innerText = "✅ Saved!";
        setTimeout(() => saveDraftBtn.innerText = originalText, 1500);
    });
}

if (draftLink) {
    draftLink.addEventListener('click', () => {
        let drafts = JSON.parse(localStorage.getItem('uniThreadDrafts')) || [];
        if (drafts.length === 0) {
            alert("You don't have any saved drafts right now.");
            return;
        }

        draftsListContainer.innerHTML = '';
        drafts.reverse().forEach(draft => {
            const safeTitle = draft.title.replace(/</g, "&lt;").replace(/>/g, "&gt;"); 
            const draftHTML = `
                <div class="draft-item" style="background: var(--bg-dark); padding: 15px; border-radius: 8px; margin-bottom: 10px; border: 1px solid var(--border-light); display: flex; justify-content: space-between; align-items: center;">
                    <div style="flex: 1; padding-right: 15px; overflow: hidden;">
                        <h4 style="color: var(--text-main); margin-bottom: 5px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${safeTitle}</h4>
                        <span style="font-size: 0.8rem; color: var(--text-muted);">${draft.date}</span>
                    </div>
                    <div style="display: flex; gap: 10px;">
                        <button class="btn-primary load-draft-btn" data-id="${draft.id}" style="padding: 6px 16px; font-size: 0.85rem;">Load</button>
                        <button class="btn-cancel delete-draft-btn" data-id="${draft.id}" style="padding: 6px 12px; font-size: 0.85rem; color: #ef4444;">Delete</button>
                    </div>
                </div>
            `;
            draftsListContainer.insertAdjacentHTML('beforeend', draftHTML);
        });

        draftsModal.style.display = 'flex';
    });
}

if (draftsListContainer) {
    draftsListContainer.addEventListener('click', (e) => {
        const loadBtn = e.target.closest('.load-draft-btn');
        const deleteBtn = e.target.closest('.delete-draft-btn');
        let drafts = JSON.parse(localStorage.getItem('uniThreadDrafts')) || [];

        if (loadBtn) {
            const draftId = loadBtn.getAttribute('data-id');
            const selectedDraft = drafts.find(d => d.id == draftId);
            if (selectedDraft) {
                titleInput.value = selectedDraft.title === "Untitled Draft" ? "" : selectedDraft.title;
                editorContent.innerHTML = selectedDraft.content || '';
                titleCounter.innerText = `${titleInput.value.length}/300`;
                if (titleInput.value.length > 0) { 
                    publishBtn.disabled = false; 
                    publishBtn.style.opacity = '1'; 
                    publishBtn.style.cursor = 'pointer'; 
                }
                draftsModal.style.display = 'none';
            }
        }

        if (deleteBtn) {
            const draftId = deleteBtn.getAttribute('data-id');
            drafts = drafts.filter(d => d.id != draftId);
            localStorage.setItem('uniThreadDrafts', JSON.stringify(drafts));
            deleteBtn.closest('.draft-item').remove();
            if (drafts.length === 0) {
                draftsModal.style.display = 'none';
            }
        }
    });
}

if (closeDraftsBtn) {
    closeDraftsBtn.addEventListener('click', () => {
        draftsModal.style.display = 'none';
    });
}
// ==========================================
// --- 🛡️ SECRET ADMIN DASHBOARD LOGIC ---
// ==========================================
const adminPanelBtn = document.getElementById('admin-panel-btn');
const adminModal = document.getElementById('admin-modal');
const closeAdminBtn = document.getElementById('close-admin-btn');
const pendingUsersList = document.getElementById('pending-users-list');

if (adminPanelBtn) {
    adminPanelBtn.addEventListener('click', () => {
        const profileDropdown = document.getElementById('profile-dropdown');
        if (profileDropdown) profileDropdown.classList.remove('show');
        adminModal.style.display = 'flex';
        loadPendingUsers();
    });
}

if (closeAdminBtn) {
    closeAdminBtn.addEventListener('click', () => {
        adminModal.style.display = 'none';
    });
}

async function loadPendingUsers() {
    if (!pendingUsersList) return;
    pendingUsersList.innerHTML = '<p style="color: var(--text-muted);">Loading...</p>';
    
    const myToken = localStorage.getItem('uniToken');
    try {
        const response = await fetch('https://unithread-backend.onrender.com/api/admin/pending', {
            headers: { 'Authorization': `Bearer ${myToken}` }
        });
        const data = await response.json();
        
        if (data.success) {
            if (data.users.length === 0) {
                pendingUsersList.innerHTML = '<p style="color: #22c55e; font-weight: 500;">✅ All caught up! No pending applications.</p>';
                return;
            }
            
            pendingUsersList.innerHTML = '';
            data.users.forEach(user => {
                const dateApplied = new Date(user.created_at).toLocaleDateString();
                const userCard = `
                    <div style="background: var(--bg-dark); padding: 15px; border-radius: 8px; margin-bottom: 10px; border: 1px solid var(--border-light); display: flex; justify-content: space-between; align-items: center;">
                        <div style="flex: 1; padding-right: 15px; overflow: hidden;">
                            <h4 style="color: var(--text-main); margin-bottom: 5px;">${user.username}</h4>
                            <p style="font-size: 0.8rem; color: var(--text-muted); margin: 0;">${user.email}</p>
                            <p style="font-size: 0.8rem; color: var(--text-muted); margin: 0;">${user.course} | ${user.year} | Applied: ${dateApplied}</p>
                        </div>
                        <div style="display: flex; gap: 10px; flex-direction: column;">
                            <button class="btn-primary approve-btn" data-email="${user.email}" style="padding: 6px 12px; font-size: 0.85rem; background: #22c55e; border-color: #22c55e;">Approve</button>
                            <button class="btn-cancel reject-btn" data-email="${user.email}" style="padding: 6px 12px; font-size: 0.85rem; color: #ef4444; border-color: #ef4444;">Reject</button>
                        </div>
                    </div>
                `;
                pendingUsersList.insertAdjacentHTML('beforeend', userCard);
            });
        } else {
            pendingUsersList.innerHTML = `<p style="color: #ef4444;">${data.message}</p>`;
        }
    } catch (error) {
        pendingUsersList.innerHTML = '<p style="color: #ef4444;">Failed to load applications.</p>';
    }
}

if (pendingUsersList) {
    pendingUsersList.addEventListener('click', async (e) => {
        const approveBtn = e.target.closest('.approve-btn');
        const rejectBtn = e.target.closest('.reject-btn');
        const myToken = localStorage.getItem('uniToken');

        if (approveBtn || rejectBtn) {
            const action = approveBtn ? 'approved' : 'rejected';
            const email = (approveBtn || rejectBtn).getAttribute('data-email');
            
            const btn = approveBtn || rejectBtn;
            const originalText = btn.innerText;
            btn.innerText = "...";
            btn.disabled = true;
            
            try {
                const response = await fetch('https://unithread-backend.onrender.com/api/admin/moderate', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${myToken}`
                    },
                    body: JSON.stringify({ email, action })
                });
                const data = await response.json();
                
                if (data.success) {
                    loadPendingUsers(); 
                } else {
                    alert("Failed: " + data.message);
                    btn.innerText = originalText;
                    btn.disabled = false;
                }
            } catch (err) {
                alert("Error processing request.");
                btn.innerText = originalText;
                btn.disabled = false;
            }
        }
    });
}