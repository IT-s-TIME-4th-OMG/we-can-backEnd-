use wecanlocaldb;

-- insert user
INSERT INTO
    user (email, password, name, nick_name, phone, img_end_point, candy, created_at, updated_at)
VALUES("test1@naver.com", "test1", "test1", "test1", "010-5133-2895", null, 100, '2024-01-06 15:30:00', '2024-01-06 15:30:00');

INSERT INTO
    user (email, password, name, nick_name, phone, img_end_point, candy, created_at, updated_at)
VALUES("test2@naver.com", "test2", "test2", "test2", "010-1234-5678", null, 100, '2024-01-06 15:30:00', '2024-01-06 15:30:00');

INSERT INTO
    user (email, password, name, nick_name, phone, img_end_point, candy, created_at, updated_at)
VALUES("test3@naver.com", "test3", "test3", "test3", "010-3474-5678", null, 100, '2024-01-06 15:30:00', '2024-01-06 15:30:00');

INSERT INTO
    user (email, password, name, nick_name, phone, img_end_point, candy, created_at, updated_at)
VALUES("test4@naver.com", "test4", "test4", "test4", "010-4383-5678", null, 100, '2024-01-06 15:30:00', '2024-01-06 15:30:00');

INSERT INTO
    user (email, password, name, nick_name, phone, img_end_point, candy, created_at, updated_at)
VALUES("test5@naver.com", "test5", "test5", "test5", "010-5454-5678", null, 100, '2024-01-06 15:30:00', '2024-01-06 15:30:00');

-- insert

INSERT INTO challenge (title, start_date, end_date, people_num, check_day, payment_type, charity_name, cover_image_endpoint, state, fine_per_once, donation_candy, total_check_num)
VALUES
    ('Challenge 1', '2024-01-04', '2024-01-05', 10, '월수금', 'TEAM', 'Charity A', 'image1.jpg', 'Active', 5, 100, 12);

INSERT INTO challenge (title, start_date, end_date, people_num, check_day, payment_type, charity_name, cover_image_endpoint, state, fine_per_once, donation_candy, total_check_num)
VALUES
    ('PERSONAL Challenge 1', '2024-01-04', '2024-01-05', 10, '월수금', 'PERSONAL', 'Charity A', 'image1.jpg', 'Active', 5, 100, 12);

-- insert user challenge

-- TEAM Challenge 참여

-- INSERT INTO user_challenge(leader, payed, fail_num, challenge_challenge_id, user_user_id)
-- VALUES (true, true, 0, 1, 1);
--
-- INSERT INTO user_challenge(leader, payed, fail_num, challenge_challenge_id, user_user_id)
-- VALUES (true, true, 1, 1, 2);
--
-- INSERT INTO user_challenge(leader, payed, fail_num, challenge_challenge_id, user_user_id)
-- VALUES (true, true, 2, 1, 3);
--
-- INSERT INTO user_challenge(leader, payed, fail_num, challenge_challenge_id, user_user_id)
-- VALUES (true, true, 3, 1, 4);
--
-- INSERT INTO user_challenge(leader, payed, fail_num, challenge_challenge_id, user_user_id)
-- VALUES (true, true, 4, 1, 5);

-- PERSONAL User Challenge 참여
INSERT INTO user_challenge(leader, payed, fail_num, challenge_challenge_id, user_user_id)
VALUES (true, true, 0, 2, 1);

INSERT INTO user_challenge(leader, payed, fail_num, challenge_challenge_id, user_user_id)
VALUES (true, true, 3, 2, 2);

INSERT INTO user_challenge(leader, payed, fail_num, challenge_challenge_id, user_user_id)
VALUES (true, true, 10, 2, 3);

INSERT INTO user_challenge(leader, payed, fail_num, challenge_challenge_id, user_user_id)
VALUES (true, true, 20, 2, 4);

INSERT INTO user_challenge(leader, payed, fail_num, challenge_challenge_id, user_user_id)
VALUES (true, true, 21, 2, 5);
