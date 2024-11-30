<!--
Hey, thanks for using the awesome-readme-template template.  
If you have any enhancements, then fork this project and create a pull request 
or just open an issue with the label "enhancement".

Don't forget to give this project a star for additional support ;)
Maybe you can mention me or this repo in the acknowledgements too
-->
<div align="center">


  <img src="위캔메인로고.png" alt="logo" width="400" height="auto" />
  <h1>벌금 기부를 통한 목표 달성 도모 서비스</h1>

  
<!-- Badges -->
<p>
  <a href="https://github.com/IT-s-TIME-4th-OMG/we-can-backEnd-/graphs/contributors">
    <img src="https://img.shields.io/github/contributors/IT-s-TIME-4th-OMG/we-can-backEnd-" alt="contributors" />
  </a>
  <a href="">
    <img src="https://img.shields.io/github/last-commit/IT-s-TIME-4th-OMG/we-can-backEnd-" alt="last update" />
  </a>
  <a href="https://github.com/IT-s-TIME-4th-OMG/we-can-backEnd-/network/members">
    <img src="https://img.shields.io/github/forks/IT-s-TIME-4th-OMG/we-can-backEnd-" alt="forks" />
  </a>
  <a href="https://github.com/IT-s-TIME-4th-OMG/we-can-backEnd-/stargazers">
    <img src="https://img.shields.io/github/stars/IT-s-TIME-4th-OMG/we-can-backEnd-" alt="stars" />
  </a>
</p>
   
<h4>
    <a href="https://drive.google.com/file/d/1nWmAliZFKF04DdUZj53G5c2Y48xZITQY/view?usp=sharing">시연 영상</a>
  <span> · </span>
    <a href="https://chlgytjd.notion.site/c519980ec8324eab90ab20e90ff20201">문서 목록</a>
  <span> · </span>
    <a href="https://drive.google.com/file/d/1jb3f55zZTQzKBJJ8S4HA02QfdkD9ePAe/view">소개 자료</a>
  </h4>
</div>

<br />

<!-- Table of Contents -->
# Table of Contents

- [About the Project](#about-the-project)
  * [Screenshots](#screenshots)
  * [Tech Stack](#tech-stack)
  * [API Sheet](#api-sheet)
  * [Features](#features)
- [Author](#author)
  

<!-- About the Project -->
## About the Project
<h4>목표를 함께 이룰 수 있는 사람들을 모집하고, 목표 달성 실패 시 걷은 벌금을 모두 기부할 수 있게 돕는 서비스입니다</h4>

<!-- Screenshots -->
### Screenshots

<div align="center"> 
  <img src="main-screen.png" width="600" alt="screenshot" />
</div>


<!-- TechStack -->
### Tech Stack

<a href="https://github.com/withtaylors/WECAN">Client</a>

<details>
  <summary>Server</summary>
  <ul>
    <li>Java 17</li>
    <li>SpringBoot 3.1.5</li>
    <li>Spring data-jpa</li>
    <li>Querydsl-jpa:5.0.0</li>
    <li>Swagger</li>
  </ul>
</details>

<details>
<summary>Database</summary>
  <ul>
    <li>MySQL</li>
    <li>Redis</li>
    <li>Elasticsearch</li>
  </ul>
</details>

<details>
<summary>DevOps</summary>
  <ul>
    <li>Docker</li>
    <li>GitHub Actions</li>
    <li>AWS EC2</li>
    <li>AWS S3</li>
    <li>Prometheus</li>
    <li>Grafana</li>
  </ul>
</details>


<!-- API Sheet -->
### API Sheet
- <a href="https://www.notion.so/API-475774be7459434ca0c281a10eb5ecfd">Notion</a>
- <a href="https://wecanomg.shop/swagger-ui/index.html">Swagger</a>

<!-- Features -->
### Features

- 메인화면
  - 내가 참여중인 챌린지, 현재 모집 중 챌린지, 굿즈샵,  챌린저들의 후기를 보여줍니다
  
- 챌린저 모집
  - 현재 모집중인 챌린지를 보여줍니다.
  - 인기순, 최신순으로 정렬이 가능하며, 챌린지의 제목으로 검색이 가능합니다.
  - 주제, 날짜, 기부방식 등 필요한 정보들을 입력하여 챌린지 모집글을 작성합니다.
  - 상세페이지에서 챌린지 참여, 찜, 댓글 작성 등이 가능하며, 모집 완료까지 남은 인원을 확인할 수 있습니다.
 
- 챌린지 캘린더
  - 모집이 성공적으로 종료되면 자동으로 챌린지가 생성되고 참여 신청을 한 사람들이 참여됩니다.
  - 챌린지가 시작되면 챌린지 캘린더 화면에서 활동 인증 사진을 게시할 수 있고, 같은 챌린지 사람들과 채팅을 할 수 있습니다.

- 후기
  - 챌린지가 종료되면 챌린지에 참여한 사람들은 해당 챌린지에 대한 후기를 작성할 수 있습니다.

- 마이페이지
  - 계정 프로필을 수정하거나 관심있는 챌린지, 현재 진행 중이거나 완료한 챌린지 등을 확인할 수 있습니다. 
  - 서비스 내에서 사용되는 재화인 candy를 구매할 수 있습니다.
 
- 캔디 결제
  - 토스페이를 통해 구현했습니다.
 
- 기부했어요
  - WECAN을 통해 기부된 내역을 기부 증서 형태로 확인할 수 있습니다


<!-- Author -->
## Author

김수진 - https://github.com/sujin11-kim


이유재 - https://github.com/Lujaec


최효성 - https://github.com/hyoseong-Choi -

Project Link: https://wecan-challenge.netlify.app/

