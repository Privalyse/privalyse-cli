import { getUserData, fetchProfile } from './api';

async function main() {
    const user = getUserData();
    console.log("User data:", user); // Should be flagged

    const profile = await fetchProfile();
    console.log(profile); // Should be flagged
}

main();
