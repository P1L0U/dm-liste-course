<template>
    <ion-page>
      <ion-header>
        <ion-toolbar>
          <ion-title class="centre">Inscription</ion-title>
        </ion-toolbar>
      </ion-header>
      <ion-content :fullscreen="true">
        <ion-header collapse="condense">
        </ion-header>
  
        <ion-item>
          <ion-label position="floating">Nom</ion-label>
          <ion-input type="text" v-model="nom"></ion-input>
        </ion-item>
        <ion-item>
          <ion-label position="floating">Prénom</ion-label>
          <ion-input type="text" v-model="prenom"></ion-input>
        </ion-item>
        <ion-item>
          <ion-label position="floating">Email</ion-label>
          <ion-input type="email" v-model="email"></ion-input>
        </ion-item>
        <ion-item>
          <ion-label position="floating">Mot de passe</ion-label>
          <ion-input type="password" v-model="mdp"></ion-input>
        </ion-item>
        <ion-item class="bouton">
        <ion-button class="bouton1" color="success" @click="Inscription()">Inscription</ion-button>
        <ion-button class="bouton2" color="success" @click="increment()">Connexion</ion-button>
        </ion-item>
        <ExploreContainer name="Tab 1 page" :number="number" />
      </ion-content>
    </ion-page>
  </template>
  
  <script>
  import { defineComponent, ref } from 'vue';
  import { IonPage, IonHeader, IonToolbar, IonTitle, IonContent, IonInput, IonItem, IonLabel, IonButton } from '@ionic/vue';
  
  export default{
    data(){
      return {
        nom:'',
        prenom:'',
        email:'',
        mdp: '',
      }
    },
    methods:{
      Inscription(){
        axios.post('/inscription', {
          nom: this.name
          prenom: this.prenom
          email: this.email
          mdp: this.mdp
        })
  
        console.log(this.name)
        console.log(this.prenom)
        console.log(this.email)
        console.log(this.mdp)
      },
    },
  }
  </script>
  
  <style lang="css">
  .centre {
    text-align: center;
  }
  
  
  .bouton1{
    margin: 3px;
    margin-left:30%;
    min-height: 20px; 
    display: flex;
    justify-content: center;
    align-items: center;
    width: 250px;
  }
  
  .bouton2{
    margin: 3px;
    margin-left: 3px;
    min-height: 20px; 
    display: flex;
    justify-content: center;
    align-items: center;
    width: 250px;
  }
  
  
  
  </style>